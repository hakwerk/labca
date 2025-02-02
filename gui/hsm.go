//go:build amd64

package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/miekg/pkcs11"
)

const CERT_FILES_PATH = "/opt/boulder/labca/certs/webpki/"

type HSMConfig struct {
	Module  string
	UserPIN string
	SOPIN   string
	SlotID  string
	Label   string
}

// HSMSession represents a session with a given PKCS#11 module. It is NOT safe for concurrent access.
type HSMSession struct {
	Context PKCSCtx
	Handle  pkcs11.SessionHandle
}

type PKCSCtx interface {
	CloseSession(pkcs11.SessionHandle) error
	CreateObject(pkcs11.SessionHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	DestroyObject(pkcs11.SessionHandle, pkcs11.ObjectHandle) error
	FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error
	FindObjectsFinal(pkcs11.SessionHandle) error
	GenerateKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	Logout(pkcs11.SessionHandle) error
	WrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, pkcs11.ObjectHandle) ([]byte, error)
}

func (cfg *HSMConfig) Initialize(ca_type string, seqnr string) {
	cfg.Module = "/usr/lib/softhsm/libsofthsm2.so"
	cfg.UserPIN = "1234"
	cfg.SOPIN = "5678"
	cfg.SlotID = "0"
	if ca_type != "root" {
		cfg.SlotID = "1"
	}
	cfg.Label = fmt.Sprintf("%s %s", ca_type, seqnr)
}

func (cfg *HSMConfig) CreateSlot() error {
	s, err := strconv.ParseUint(cfg.SlotID, 10, 32)
	if err != nil {
		return fmt.Errorf("failed to convert slot id '%s' to uint: %s", cfg.SlotID, err.Error())
	}
	id, err := cfg.createSlot(uint(s), cfg.Label)
	if err != nil {
		return fmt.Errorf("failed to create slot: %s", err.Error())
	}
	cfg.SlotID = id

	return nil
}

func findSlotWithLabel(ctx *pkcs11.Ctx, label string, missing_ok bool) (string, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return "", fmt.Errorf("failed to get slots list: %s", err)
	}

	for _, slot := range slots {
		info, err := ctx.GetSlotInfo(slot)
		if err != nil {
			return "", fmt.Errorf("failed to get slot info: %s", err)
		}

		if info.Flags&pkcs11.CKF_TOKEN_PRESENT == pkcs11.CKF_TOKEN_PRESENT {
			token, err := ctx.GetTokenInfo(slot)
			if err != nil {
				return "", fmt.Errorf("failed to get token info: %s", err)
			}

			if token.Label == label {
				return fmt.Sprint(slot), nil
			}
		}
	}

	if missing_ok {
		return "", nil
	}

	return "", errors.New("no slot found matching this label")
}

func (cfg *HSMConfig) createSlot(slotId uint, label string) (string, error) {
	ctx := pkcs11.New(cfg.Module)
	if ctx == nil {
		return "", errors.New("failed to load pkcs11 module")
	}
	err := ctx.Initialize()
	if err != nil && err.Error() != "pkcs11: 0x191: CKR_CRYPTOKI_ALREADY_INITIALIZED" {
		return "", fmt.Errorf("failed to initialize pkcs11 context: %s", err)
	}

	slot, err := findSlotWithLabel(ctx, label, true)
	if err != nil {
		return "", err
	}
	if slot != "" {
		return slot, nil
	}

	// No slot found with this token label, so create a new one
	err = ctx.InitToken(slotId, cfg.SOPIN, label)
	if err != nil {
		if strings.Contains(err.Error(), "0x3: CKR_SLOT_ID_INVALID") {
			slots, err := ctx.GetSlotList(true)
			if err != nil {
				return "", fmt.Errorf("failed to initialize token, failed to get slot list: %s", err)
			}
			slotId = uint(len(slots) - 1)
			cfg.SlotID = fmt.Sprint(slotId)
			err = ctx.InitToken(slotId, cfg.SOPIN, label)
			if err != nil {
				return "", fmt.Errorf("failed to initialize token with id %d: %s", slotId, err)
			}
		} else {
			return "", fmt.Errorf("failed to initialize token: %s", err)
		}
	}

	session, err := ctx.OpenSession(slotId, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return "", fmt.Errorf("failed to open session: %s", err)
	}
	defer ctx.CloseSession(session)

	err = ctx.Login(session, pkcs11.CKU_SO, cfg.SOPIN)
	if err != nil {
		if err.Error() == "pkcs11: 0xA0: CKR_PIN_INCORRECT" {
			return "", errors.New("incorrect SO PIN")
		} else {
			return "", fmt.Errorf("failed to login: %s", err)
		}
	}
	defer ctx.Logout(session)

	err = ctx.InitPIN(session, cfg.UserPIN)
	if err != nil {
		return "", fmt.Errorf("failed to initialize pin: %s", err)
	}

	// Forced reconnect to get the renumbered slots from SoftHSM2
	ctx.Finalize()
	ctx.Destroy()
	ctx = pkcs11.New(cfg.Module)
	if ctx == nil {
		return "", errors.New("failed to reload pkcs11 module")
	}
	err = ctx.Initialize()
	if err != nil && err.Error() != "pkcs11: 0x191: CKR_CRYPTOKI_ALREADY_INITIALIZED" {
		return "", fmt.Errorf("failed to reinitialize pkcs11 context: %s", err)
	}

	slot, err = findSlotWithLabel(ctx, label, false)
	if err != nil {
		return "", err
	}
	if slot != "" {
		return slot, nil
	}

	return "", errors.New("failed to create slot")
}

// getSession establishes a logged in session on a pkcs11 slot.
//
// Don't forget to call .Close() on the resulting session when done!
func (cfg *HSMConfig) getSession() (*HSMSession, error) {
	ctx := pkcs11.New(cfg.Module)
	if ctx == nil {
		return nil, errors.New("failed to load pkcs11 module")
	}
	err := ctx.Initialize()
	if err != nil && err.Error() != "pkcs11: 0x191: CKR_CRYPTOKI_ALREADY_INITIALIZED" {
		return nil, fmt.Errorf("failed to initialize pkcs11 context: %s", err)
	}

	slot, err := findSlotWithLabel(ctx, cfg.Label, true)
	if err != nil {
		return nil, err
	}
	if slot == "" {
		return nil, nil
	}

	s, err := strconv.ParseUint(slot, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to convert slot id '%s' to uint: %s", cfg.SlotID, err.Error())
	}

	session, err := ctx.OpenSession(uint(s), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %s", err)
	}

	err = ctx.Login(session, pkcs11.CKU_USER, cfg.UserPIN)
	if err != nil {
		if err.Error() == "pkcs11: 0xA0: CKR_PIN_INCORRECT" {
			return nil, errors.New("incorrect user PIN")
		} else {
			return nil, fmt.Errorf("failed to login: %s", err)
		}
	}

	return &HSMSession{ctx, session}, nil
}

func (cfg *HSMConfig) ClearAll() error {
	hs, err := cfg.getSession()
	if err != nil {
		return fmt.Errorf("failed to get session: %s", err)
	}
	defer hs.Close()

	err = hs.DestroyAllObjects(cfg.Label)
	if err != nil {
		return err
	}

	return nil
}

func arrConcat(arrays ...[]byte) []byte {
	out := make([]byte, len(arrays[0]))
	copy(out, arrays[0])
	for _, array := range arrays[1:] {
		out = append(out, array...)
	}

	return out
}

func arrXor(arrL []byte, arrR []byte) []byte {
	out := make([]byte, len(arrL))
	for x := range arrL {
		out[x] = arrL[x] ^ arrR[x]
	}
	return out
}

// AES Key Wrap algorithm is specified in RFC 3394
func UnwrapKey(block cipher.Block, cipherText []byte) ([]byte, error) {
	//Initialize variables
	a := make([]byte, 8)
	n := (len(cipherText) / 8) - 1

	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], cipherText[(i+1)*8:])
	}
	copy(a, cipherText[:8])

	//Compute intermediate values
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := (n * j) + i
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, uint64(t))

			b := arrConcat(arrXor(a, tBytes), r[i-1])
			block.Decrypt(b, b)

			copy(a, b[:len(b)/2])
			copy(r[i-1], b[len(b)/2:])
		}
	}

	var defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	if subtle.ConstantTimeCompare(a, defaultIV) != 1 {
		return nil, errors.New("integrity check failed - unexpected IV")
	}

	//Output
	c := arrConcat(r...)
	return c, nil
}

func (cfg *HSMConfig) GetPrivateKey() ([]byte, error) {
	hs, err := cfg.getSession()
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %s", err)
	}
	defer hs.Close()

	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(cfg.Label)),
	}

	keyHandle, err := hs.FindObject(tmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to find private key with label='%s': %w", cfg.Label, err)
	}

	// Generate a temporary wrapping key in memory
	mechs := []*pkcs11.Mechanism{
		// pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -M | grep -v generate_key_pair | grep generate
		pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil),
	}
	tmpl = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 16),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
	}
	wrapKeyHandle, err := hs.GenerateKey(mechs, tmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wrapping key: %w", err)
	}

	// Extract the key value
	tmpl = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	wrapKeyAttrs, err := hs.GetAttributeValue(wrapKeyHandle, tmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to get attribute values from object: %w", err)
	}
	var wrapKey []byte
	for _, wrapKeyAttr := range wrapKeyAttrs {
		switch wrapKeyAttr.Type {
		case pkcs11.CKA_VALUE:
			wrapKey = wrapKeyAttr.Value
		default:
			if wrapKeyAttr.Value == nil {
				fmt.Printf("unexpected attribute #%d: nil\n", wrapKeyAttr.Type)
			} else {
				fmt.Printf("unexpected attribute #%d: %s / %s\n", wrapKeyAttr.Type, hex.EncodeToString(wrapKeyAttr.Value), wrapKeyAttr.Value)
			}
		}
	}

	// Wrap the private key on the HSM
	mechs = []*pkcs11.Mechanism{
		// pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so -M | grep wrap
		pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil),
	}
	wrappedKey, err := hs.WrapKey(mechs, wrapKeyHandle, keyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap private key: %w", err)
	}

	// Unwrap the key locally
	c, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create new aes cipher: %w", err)
	}
	key, err := UnwrapKey(c, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	return key, nil
}

func loadKey(filename string) (crypto.PrivateKey, crypto.PublicKey, error) {
	var priv crypto.PrivateKey
	var pub crypto.PublicKey

	keyPEM, err := os.ReadFile(filename)
	if err != nil {
		return priv, pub, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return priv, pub, fmt.Errorf("no data in key PEM file %s", filename)
	}

	parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	if reflect.TypeOf(parseResult).String() == "*rsa.PrivateKey" {
		k := parseResult.(*rsa.PrivateKey)
		priv = k
		pub = k.PublicKey
	} else if reflect.TypeOf(parseResult).String() == "*ecdsa.PrivateKey" {
		k := parseResult.(*ecdsa.PrivateKey)
		priv = k
		pub = k.PublicKey
	} else {
		return priv, pub, fmt.Errorf("unknown private key type '%s'", reflect.TypeOf(parseResult).String())
	}

	if priv == nil {
		fmt.Printf("WARNING: unknown private key type for %+v\n", parseResult)
		return priv, pub, errors.New("unknown private key type")
	}

	return priv, pub, nil
}

func loadCert(filename string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no data in certificate PEM file %s", filename)
	}

	parseResult, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate: %s", err.Error())
	}

	return parseResult, nil
}

var curveToOIDDER = map[string][]byte{
	elliptic.P224().Params().Name: {6, 5, 43, 129, 4, 0, 33},
	elliptic.P256().Params().Name: {6, 8, 42, 134, 72, 206, 61, 3, 1, 7},
	elliptic.P384().Params().Name: {6, 5, 43, 129, 4, 0, 34},
	elliptic.P521().Params().Name: {6, 5, 43, 129, 4, 0, 35},
}

func storePubKey(hs *HSMSession, pubKey crypto.PublicKey, keyID []byte, label string) error {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)),
	}

	if reflect.TypeOf(pubKey).String() == "rsa.PublicKey" {
		p := pubKey.(rsa.PublicKey)

		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_MODULUS, p.N.Bytes()))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(p.E)).Bytes()))
	} else if reflect.TypeOf(pubKey).String() == "ecdsa.PublicKey" {
		p := pubKey.(ecdsa.PublicKey)
		eh, err := p.ECDH()
		if err != nil {
			return fmt.Errorf("failed to convert ecdsa pubkey to ecdh: %s", err.Error())
		}

		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC))

		encodedCurve := curveToOIDDER[p.Curve.Params().Name]
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedCurve))

		rawValue := asn1.RawValue{
			Tag:   asn1.TagOctetString,
			Bytes: eh.Bytes(),
		}
		marshalledPoint, err := asn1.Marshal(rawValue)
		if err != nil {
			return fmt.Errorf("failed to marshall ecdsa point: %s", err.Error())
		}
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, marshalledPoint))

	} else {
		return fmt.Errorf("unknown public key type '%s'", reflect.TypeOf(pubKey).String())
	}

	_, err := hs.CreateObject(tmpl)
	if err != nil {
		fmt.Printf("failed to create public key on HSM: %s\n", err.Error())
		return err
	}

	return nil
}

func storePrivKey(hs *HSMSession, privKey crypto.PrivateKey, keyID []byte, label string, extractable bool) error {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP_WITH_TRUSTED, false),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)),
	}

	if reflect.TypeOf(privKey).String() == "*rsa.PrivateKey" {
		k := privKey.(*rsa.PrivateKey)

		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_MODULUS, k.PublicKey.N.Bytes()))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(k.PublicKey.E)).Bytes()))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, big.NewInt(int64(k.E)).Bytes()))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, new(big.Int).Set(k.Primes[0]).Bytes()))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, new(big.Int).Set(k.Primes[1]).Bytes()))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, new(big.Int).Set(k.Precomputed.Dp).Bytes()))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, new(big.Int).Set(k.Precomputed.Dq).Bytes()))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, new(big.Int).Set(k.Precomputed.Qinv).Bytes()))

	} else if reflect.TypeOf(privKey).String() == "*ecdsa.PrivateKey" {
		k := privKey.(*ecdsa.PrivateKey)

		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC))
		encodedCurve := curveToOIDDER[k.Params().Name]
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedCurve))
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_VALUE, new(big.Int).Set(k.D).Bytes()))

	} else {
		return fmt.Errorf("unknown private key type '%s'", reflect.TypeOf(privKey).String())
	}

	_, err := hs.CreateObject(tmpl)
	if err != nil {
		fmt.Printf("failed to create private key on HSM: %s\n", err.Error())
		return err
	}

	return nil
}

func storeCertificate(hs *HSMSession, certificate *x509.Certificate, keyID []byte, label string) error {
	serial, err := asn1.Marshal(certificate.SerialNumber)
	if err != nil {
		return err
	}

	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, certificate.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, certificate.RawIssuer),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, serial),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, certificate.Raw),
	}

	_, err = hs.CreateObject(tmpl)
	if err != nil {
		fmt.Printf("failed to create certificate on HSM: %s\n", err.Error())
		return err
	}

	return nil
}

func (cfg *HSMConfig) ImportKeyCert(keyFile, certFile string) (crypto.PublicKey, error) {
	hs, err := cfg.getSession()
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %s", err)
	}
	defer hs.Close()

	privKey, pubKey, err := loadKey(keyFile)
	if err != nil {
		return pubKey, err
	}

	keyID := make([]byte, 4)
	_, err = rand.Read(keyID)
	if err != nil {
		return pubKey, err
	}

	err = storePubKey(hs, pubKey, keyID, cfg.Label)
	if err != nil {
		fmt.Printf("failed to store public key on HSM: %s\n", err.Error())
		return pubKey, err
	}

	extractable := true // For now, with SoftHSM, this is fine. In future we need to ask for informed consent!

	err = storePrivKey(hs, privKey, keyID, cfg.Label, extractable)
	if err != nil {
		fmt.Printf("failed to store private key on HSM: %s\n", err.Error())
		return pubKey, err
	}

	if strings.Index(filepath.Base(keyFile), "root-") != 0 {
		jsonFile := path.Join(CERT_FILES_PATH, filepath.Base(keyFile))
		jsonFile = strings.Replace(jsonFile, "-key.pem", ".pkcs11.json", -1)
		contents := fmt.Sprintf(`{"module": %q, "tokenLabel": %q, "pin": %q}`, cfg.Module, cfg.Label, cfg.UserPIN)
		err = os.WriteFile(jsonFile, []byte(contents), 0644)
		if err != nil {
			return pubKey, fmt.Errorf("failed to write '%s' file: %s", jsonFile, err.Error())
		}
	}

	if certFile != "" {
		cert, err := loadCert(certFile)
		if err != nil {
			return pubKey, err
		}

		err = storeCertificate(hs, cert, keyID, cfg.Label)
		if err != nil {
			fmt.Printf("failed to store certificate on HSM: %s\n", err.Error())
			return pubKey, err
		}
	}

	return pubKey, nil
}

func (hs *HSMSession) Close() {
	hs.Context.CloseSession(hs.Handle)
	hs.Context.Logout(hs.Handle)
}

func (hs *HSMSession) CreateObject(tmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return hs.Context.CreateObject(hs.Handle, tmpl)
}

func (hs *HSMSession) DestroyObject(object pkcs11.ObjectHandle) error {
	return hs.Context.DestroyObject(hs.Handle, object)
}

func (hs *HSMSession) DestroyAllObjects(label string) error {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)),
	}

	keys, err := hs.FindObjects(tmpl)
	if err != nil {
		return fmt.Errorf("failed to find objects with label='%s': %w", label, err)
	}

	for _, key := range keys {
		err = hs.DestroyObject(key)
		if err != nil {
			return fmt.Errorf("failed to destroy object '%+v': %w", key, err)
		}
	}

	return nil
}

func (hs *HSMSession) FindObject(tmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	err := hs.Context.FindObjectsInit(hs.Handle, tmpl)
	if err != nil {
		return 0, err
	}
	handles, _, err := hs.Context.FindObjects(hs.Handle, 2)
	if err != nil {
		return 0, err
	}
	err = hs.Context.FindObjectsFinal(hs.Handle)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, errors.New("no objects found matching provided template")
	}
	if len(handles) > 1 {
		return 0, fmt.Errorf("too many objects (%d) that match the provided template", len(handles))
	}
	return handles[0], nil
}

func (hs *HSMSession) FindObjects(tmpl []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	result := []pkcs11.ObjectHandle{}

	err := hs.Context.FindObjectsInit(hs.Handle, tmpl)
	if err != nil {
		return result, err
	}

	for {
		handles, _, err := hs.Context.FindObjects(hs.Handle, 10)
		if err != nil {
			return result, err
		}
		if len(handles) == 0 {
			break
		}
		result = append(result, handles...)
	}

	err = hs.Context.FindObjectsFinal(hs.Handle)
	if err != nil {
		return result, err
	}

	return result, nil
}

func (hs *HSMSession) GenerateKey(mechs []*pkcs11.Mechanism, tmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return hs.Context.GenerateKey(hs.Handle, mechs, tmpl)
}

func (hs *HSMSession) GetAttributeValue(handle pkcs11.ObjectHandle, tmpl []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	return hs.Context.GetAttributeValue(hs.Handle, handle, tmpl)
}

func (hs *HSMSession) WrapKey(mechs []*pkcs11.Mechanism, wkh pkcs11.ObjectHandle, kh pkcs11.ObjectHandle) ([]byte, error) {
	return hs.Context.WrapKey(hs.Handle, mechs, wkh, kh)
}
