function positionFooter() {
    var page = $("div#page-wrapper");
    $("#footer").parent().css("padding-top", "0px");
    var usedHeight = 0;
    page.children().each(function() {
        usedHeight += $(this).outerHeight();
    });
    var offset = page.outerHeight() - usedHeight - 2;
    if (offset < 0 ) {
        offset = 0;
    }
    $("#footer").parent().css("padding-top", offset + "px");
}

$(function() {
    if ( $.fn.dataTable) {
        $.fn.dataTable.render.ellipsis = function ( cutoff, wordbreak, escapeHtml ) {
            var esc = function ( t ) {
                return t
                    .replace( /&/g, '&amp;' )
                    .replace( /</g, '&lt;' )
                    .replace( />/g, '&gt;' )
                    .replace( /"/g, '&quot;' );
            };

            return function ( d, type, row ) {
                // Order, search and type get the original data
                if ( type !== 'display' ) {
                    return d;
                }

                if ( typeof d !== 'number' && typeof d !== 'string' ) {
                    return d;
                }

                d = d.toString(); // cast numbers

                if ( d.length < cutoff ) {
                    return d;
                }

                var shortened = d.substr(0, cutoff-1);

                // Find the last white space character in the string
                if ( wordbreak ) {
                    shortened = shortened.replace(/\s([^\s]*)$/, '');
                }

                // Protect against uncontrolled HTML input
                if ( escapeHtml ) {
                    shortened = esc( shortened );
                }

                return '<span class="ellipsis" title="'+esc(d)+'">'+shortened+'&#8230;</span>';
            };
        };

        /*
         * Natural Sort algorithm for Javascript - Version 0.7 - Released under MIT license
         * Author: Jim Palmer (based on chunking idea from Dave Koelle)
         * Contributors: Mike Grier (mgrier.com), Clint Priest, Kyle Adams, guillermo
         * See: http://js-naturalsort.googlecode.com/svn/trunk/naturalSort.js
         */
        function naturalSort (a, b, html) {
            var re = /(^-?[0-9]+(\.?[0-9]*)[df]?e?[0-9]?%?$|^0x[0-9a-f]+$|[0-9]+)/gi,
                sre = /(^[ ]*|[ ]*$)/g,
                dre = /(^([\w ]+,?[\w ]+)?[\w ]+,?[\w ]+\d+:\d+(:\d+)?[\w ]?|^\d{1,4}[\/\-]\d{1,4}[\/\-]\d{1,4}|^\w+, \w+ \d+, \d{4})/,
                hre = /^0x[0-9a-f]+$/i,
                ore = /^0/,
                htmre = /(<([^>]+)>)/ig,
                // convert all to strings and trim()
                x = a.toString().replace(sre, '') || '',
                y = b.toString().replace(sre, '') || '';
                // remove html from strings if desired
                if (!html) {
                    x = x.replace(htmre, '');
                    y = y.replace(htmre, '');
                }
                // chunk/tokenize
            var xN = x.replace(re, '\0$1\0').replace(/\0$/,'').replace(/^\0/,'').split('\0'),
                yN = y.replace(re, '\0$1\0').replace(/\0$/,'').replace(/^\0/,'').split('\0'),
                // numeric, hex or date detection
                xD = parseInt(x.match(hre), 10) || (xN.length !== 1 && x.match(dre) && Date.parse(x)),
                yD = parseInt(y.match(hre), 10) || xD && y.match(dre) && Date.parse(y) || null;

            // first try and sort Hex codes or Dates
            if (yD) {
                if ( xD < yD ) {
                    return -1;
                }
                else if ( xD > yD ) {
                    return 1;
                }
            }

            // natural sorting through split numeric strings and default strings
            for(var cLoc=0, numS=Math.max(xN.length, yN.length); cLoc < numS; cLoc++) {
                // find floats not starting with '0', string or 0 if not defined (Clint Priest)
                var oFxNcL = !(xN[cLoc] || '').match(ore) && parseFloat(xN[cLoc], 10) || xN[cLoc] || 0;
                var oFyNcL = !(yN[cLoc] || '').match(ore) && parseFloat(yN[cLoc], 10) || yN[cLoc] || 0;
                // handle numeric vs string comparison - number < string - (Kyle Adams)
                if (isNaN(oFxNcL) !== isNaN(oFyNcL)) {
                    return (isNaN(oFxNcL)) ? 1 : -1;
                }
                // rely on string comparison if different types - i.e. '02' < 2 != '02' < '2'
                else if (typeof oFxNcL !== typeof oFyNcL) {
                    oFxNcL += '';
                    oFyNcL += '';
                }
                if (oFxNcL < oFyNcL) {
                    return -1;
                }
                if (oFxNcL > oFyNcL) {
                    return 1;
                }
            }
            return 0;
        }

        jQuery.extend( jQuery.fn.dataTableExt.oSort, {
            "natural-asc": function ( a, b ) {
                return naturalSort(a,b,true);
            },

            "natural-desc": function ( a, b ) {
                return naturalSort(a,b,true) * -1;
            },

            "natural-nohtml-asc": function( a, b ) {
                return naturalSort(a,b,false);
            },

            "natural-nohtml-desc": function( a, b ) {
                return naturalSort(a,b,false) * -1;
            },

            "natural-ci-asc": function( a, b ) {
                a = a.toString().toLowerCase();
                b = b.toString().toLowerCase();

                return naturalSort(a,b,true);
            },

            "natural-ci-desc": function( a, b ) {
                a = a.toString().toLowerCase();
                b = b.toString().toLowerCase();

                return naturalSort(a,b,true) * -1;
            }
        } );
    }

    $('#o').blur(function() {
        var prefix = $(this).val().split(" ")[0];

        if ((prefix != "") && (($("#cn").val() == "Root CA") || ($("#cn").val() == "CA")) && ($(this).parent().parent().find(".error").length == 1)) {
            $("#cn").val(prefix + " " + $("#cn").val());
        }
    });

    function radioDisable() {
        $("input[type=radio]").each(function() {
            $("#" + $(this).attr('id') + "_domains").prop('readonly', !$(this).prop('checked'));
        });

        if ($("input[type=radio]#whitelist").prop('checked') || $("input[type=radio]#standard").prop('checked') ) {
            $("#domain_mode_warning").show();
            $("#ld_options").hide();
        } else {
            $("#domain_mode_warning").hide();
            $("#ld_options").show();
        }
    }

    $("input[type=radio]").change(function() {
        radioDisable();
    });

    $("#domain_mode_warning").hide();
    $("#ld_options").show();
    radioDisable();


    $( window ).resize(function() {
        positionFooter();
    });

    $("#restart-button").click(function(evt) {
        $("#pre-restart-1").hide();
        $("#pre-restart-2").hide();
        $("#restarting").removeClass("hidden");
        $("#restarting").show();
        $(window).resize();

        var args = [ "unknown" ];
        if (window.location.href.indexOf('?') > 0 ) {
            var tmp = window.location.href.split('?');
            if (tmp.length > 1) {
                args = tmp[1].split('=');
            }
        }
        var secret = "";
        var nextPath = "";
        if (args[0] == "restart") {
            secret = args[1];
            nextPath = "/restart";
        }

        var pollTimer;

        var baseUrl = window.location.href;
        if (baseUrl.indexOf("?") > 0) {
            baseUrl = baseUrl.substr(0, baseUrl.indexOf("?"));
        }
        if (baseUrl.endsWith("/wait")) {
            baseUrl = baseUrl.substr(0, baseUrl.length-5);
        }
        $.ajax(baseUrl + nextPath, {
            data: {
                token: secret,
            },
            timeout: 30000
        })
        .done(function(data) {
            clearInterval(pollTimer);
            window.location.href = baseUrl + "/setup";
        })
        .fail(function(xhr, status, err) {
            nextPath = "";
            // Assume that the restart was initiated... Wait for server to be available again.
            var ctr = 0;
            pollTimer = setInterval(pollServer, 3000);

            function pollServer() {
                if (ctr > 59) {
                    clearInterval(pollTimer);
                    $("img#restart-spinner").parent().text("timeout").addClass("error");
                } else if (ctr < 10) {
                    // No need to try immediately, the server is restarting
                    ctr++;
                } else {
                    $.ajax(baseUrl + nextPath, {
                        timeout: 2500
                    })
                    .done(function(data) {
                        clearInterval(pollTimer);
                        window.location.href = baseUrl;
                    })
                    .fail(function(xhr, status, err) {
                        ctr++;
                        if ((typeof err === 'undefined' || err === "") && status === "error") {
                            // Probably because the certificate has changed
                            clearInterval(pollTimer);
                            window.location.href = baseUrl;
                        }
                    });
                }
            }
        });

        return false;
    });

    if ( $("img#wrapup-spinner").length ) {
        var targetUrl = window.location.href.replace("/setup", "/final");
        var ctr = 0;
        var pollTimer = setInterval(pollServer, 5000);

        function pollServer() {
            if (ctr > 60) {
                clearInterval(pollTimer);
                $("img#wrapup-spinner").parent().text("timeout").addClass("error");
            } else if (ctr < 5) {
                // No need to try immediately, the server won't be ready this quick
                ctr++;
            } else {
                $.ajax(targetUrl, {
                    timeout: 4500
                })
                .done(function(data) {
                    if (data.error) {
                        clearInterval(pollTimer);
                        targetUrl = targetUrl.replace("/final", "/error");
                        window.location.href = targetUrl;
                    } else if (data.complete) {
                        clearInterval(pollTimer);
                        targetUrl = targetUrl.replace("/final", "");
                        window.location.href = targetUrl;
                    }
                })
                .fail(function(xhr, status, err) {
                    ctr++;
                    if ((typeof err === 'undefined' || err === "") && status === "error") {
                        // Probably because the certificate has changed
                        clearInterval(pollTimer);
                        window.location.href = targetUrl;
                    }
                });
            }
        }
    }

    $("#cert-revoke-btn").click(function(evt) {
        if ( $("#revoke-reason").val() == "" ) {
            alert("You must select a reason");
        } else {
            $.ajax(window.location.href, {
                method: "POST",
                data: {
                    serial: $("#revoke-serial").val(),
                    reason: $("#revoke-reason").val(),
                },
            })
            .done(function(data) {
                window.location.reload();
            })
            .fail(function(xhr, status, err) {
                alert(err);
                window.location.href = window.location.href + "/../../logs/labca";
            });
        }
    });

    $("#use-https").click(function(evt) {
        $("#acme-server").prop('readonly', !$(this).prop('checked'));
    });
    $("#acme-server").prop('readonly', !$("#use-https").prop('checked'));

    $(document).ready(function() {
        if ( $(".datatable").length ) {
            var options = {
                pageLength: 25,
            };

            if ( $('.orders_list').length || $('.rel_orders_list').length ) {
                col = 2;
                if ( $('.backend_stepca').length ) {
                    col = 1;
                }
                options["columnDefs"] = [ {
                        targets: col,
                        render: $.fn.dataTable.render.ellipsis(15)
                    } ];
            }

            if ( $('.certificates_list').length || $('.rel_certificates_list').length ) {
                col = 2;
                if ( $('.backend_stepca').length ) {
                    col = 1;
                }
                options["columnDefs"] = [ {
                        targets: col,
                        render: $.fn.dataTable.render.ellipsis(15)
                    } ];
            }

            if ( $('.authz_list').length || $('.rel_authz_list').length ) {
                if ( $('.backend_stepca').length ) {
                    options["columnDefs"] = [
                        {
                            targets: 1,
                            render: $.fn.dataTable.render.ellipsis(15),
                        },
                    ];
                } else {
                    options["columnDefs"] = [
                        {
                            targets: 0,
                            render: $.fn.dataTable.render.ellipsis(15),
                            type: 'natural'
                        },
                    ];
                }
            }

            if ( $('.challenges_list').length || $('.rel_challenges_list').length ) {
                if ( $('.backend_stepca').length ) {
                    options["columnDefs"] = [
                        {
                            targets: 1,
                            render: $.fn.dataTable.render.ellipsis(15)
                        },
                    ];
                } else {
                    options["columnDefs"] = [
                        {
                            targets: 1,
                            render: $.fn.dataTable.render.ellipsis(15)
                        },
                        {
                            targets: 5,
                            render: $.fn.dataTable.render.ellipsis(15)
                        }
                    ];
                }
            }

            var table = $(".datatable").DataTable( options );

            $('.accounts_list tbody').on('click', 'tr', function () {
                var data = table.row( this ).data();
                window.location = window.location + '/' + data[0]
            });

            $('.orders_list tbody').on('click', 'tr', function () {
                var data = table.row( this ).data();
                window.location = window.location + '/' + data[0]
            });

            $('.rel_orders_list tbody').on('click', 'tr', function () {
                var data = table.row( this ).data();
                window.location = window.location + '/../../orders/' + data[0]
            });

            $('.authz_list tbody').on('click', 'tr', function () {
                var data = table.row( this ).data();
                window.location = window.location + '/' + data[0]
            });

            $('.rel_authz_list tbody').on('click', 'tr', function () {
                var data = table.row( this ).data();
                window.location = window.location + '/../../authz/' + data[0]
            });

            $('.challenges_list tbody').on('click', 'tr', function () {
                var data = table.row( this ).data();
                window.location = window.location + '/' + data[0]
            });

            $('.rel_challenges_list tbody').on('click', 'tr', function () {
                var data = table.row( this ).data();
                window.location = window.location + '/../../challenges/' + data[0]
            });

            $('.certificates_list tbody').on('click', 'tr', function () {
                var data = table.row( this ).data();
                window.location = window.location.href.split('?')[0] + '/' + data[0]
            });

            $('.rel_certificates_list tbody').on('click', 'tr', function () {
                var data = table.row( this ).data();
                if (data) {
                    window.location = window.location + '/../../certificates/' + data[0]
                }
            });

            $('.auth_show tbody tr').children().each(function () {
                if (this.textContent == 'Validation Error' || this.textContent == 'Validation Record') {
                    console.log(this.nextElementSibling);
                    this.nextElementSibling.innerText = JSON.stringify(JSON.parse(this.nextElementSibling.innerText), null, 2);
                    $(this.nextElementSibling).wrapInner('<pre class="json"></pre>');
                }
            });

            $(".datatable").on('draw.dt', positionFooter);
        }

        $(".datatable").each(function(idx, val) {
            var table = $(val).DataTable();
            classes = $(val).attr('class').split(" ");

            if ( classes.indexOf("accounts_list") > -1  ) {
                col = 0;
                if ( classes.indexOf("backend_stepca") > -1 ) {
                    col = 3;
                }
                table.columns(col).order( 'desc' ).draw();
            }

            if ( classes.indexOf("certificates_list") > -1 || classes.indexOf("rel_certificates_list") > -1 ) {
                col = 0;
                if ( classes.indexOf("backend_stepca") > -1 ) {
                    col = 5;
                }
                table.columns(col).order( 'desc' ).draw();
            }

            if ( classes.indexOf("orders_list") > -1 || classes.indexOf("rel_orders_list") > -1 ) {
                col = 0;
                if ( classes.indexOf("backend_stepca") > -1 ) {
                    col = 4;
                }
                table.columns(col).order( 'desc' ).draw();
            }

            if ( classes.indexOf("authz_list") > -1 || classes.indexOf("rel_authz_list") > -1 ) {
                col = 0;
                if ( classes.indexOf("backend_stepca") > -1 ) {
                    col = 4;
                }
                table.columns(col).order( 'desc' ).draw();
            }

            if ( classes.indexOf("challenges_list") > -1 || classes.indexOf("rel_challenges_list") > -1 ) {
                col = 0;
                if ( classes.indexOf("backend_stepca") > -1 ) {
                    col = 4;
                }
                table.columns(col).order( 'desc' ).draw();
            }
        });

        setTimeout(function() {
            $(window).resize();
        }, 10);
    });
});
