
function pwduxInit(barSel, pwdSel) {
    $(barSel).css("width", $(pwdSel).outerWidth());

    $(".vizpwd").each(function(idx) {
        if ( $(this).prev().outerWidth() > 0 ) {
            $(this).css("margin-left", $(this).prev().outerWidth() - $(this).outerWidth() - 4);
        }
    });
}

function pwduxReset(barSel) {
    $(barSel + ' div').removeClass().addClass('progress-bar');
    $(barSel + ' div').addClass('strength-none').css('width', "0%");
}

function pwduxHandlers(barSel, pwdSel, blckSels) {
    $(pwdSel).keyup(function() {
        $(barSel).css('width', $(pwdSel).outerWidth());
        $(barSel + ' div').removeClass().addClass('progress-bar');

        if ($(pwdSel).val().length == 0) {
            $(barSel + ' div').addClass('strength-none').css('width', "0%");
        } else {
            blacklist = ['labca', 'acme'];
            if (blckSels) {
                blckSels.forEach(function(blckSel) {
                    v = $(blckSel).val();
                    if (v.indexOf('@') > 0) {
                        d = v.split('@')[1];
                        v = v.split('@')[0];
                        for (i=0; i<d.split('.').length-1; i++) {
                            blacklist.push(d.split('.')[i]);
                        }
                    }
                    blacklist.push(v);
                });
            }

            cls = 'strength-bad';
            strength = zxcvbn($(pwdSel).val(), blacklist);
            $(barSel).attr('title', strength.feedback.warning);
            strength = strength.score;
            if (strength >= 3) {
                cls = 'strength-good';
            } else if (strength >= 2) {
                cls = 'strength-med';
            }
            $(barSel + ' div').addClass(cls).css('width', (100*strength/4)+'%');
        }
    });

    $('input[type=password]').focus(function() {
        if ($(this).next().hasClass('vizpwd') && $(this).val() == "") {
            $(this).next().data('active', 1);
        }
    });

    $('input[type=password]').keyup(function() {
        if ($(this).next().hasClass('vizpwd') && $(this).val() == "") {
            $(this).next().data('active', 1);
        }
    });

    $('input[type=password]').blur(function() {
        if ($(this).next().hasClass('vizpwd')) {
            $(this).next().data('active', 0);
        }
    });

    $('.vizpwd').mousedown(function() {
        if ($(this).data('active')) {
            $(this).prev().attr('type', 'text');
            viz = $(this);
            setTimeout(function() {
                viz.data('active', 1);
            }, 100);
        }
    });

    $('.vizpwd').mouseup(function() {
        $(this).prev().attr('type', 'password');
        $(this).prev().focus();
    });
}
