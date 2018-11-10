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
    console.log("applying offset of " + offset);
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
    }

    $('#o').blur(function() {
        var prefix = $(this).val().split(" ")[0];

        if ((prefix != "") && (($("#cn").val() == "Root CA") || ($("#cn").val() == "CA")) && ($(this).parent().parent().find(".error").length == 0)) {
            $("#cn").val(prefix + " " + $("#cn").val());
        }
    });

    function radioDisable() {
        $("input[type=radio]").each(function() {
            $("#" + $(this).attr('id') + "_domains").prop('readonly', !$(this).prop('checked'));
        });

        if ($("input[type=radio]#whitelist").prop('checked') || $("input[type=radio]#standard").prop('checked') ) {
            $("#domain_mode_warning").show();
        } else {
            $("#domain_mode_warning").hide();
        }
    }

    $("input[type=radio]").change(function() {
        radioDisable();
    });

    $("#domain_mode_warning").hide();
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

        var args = window.location.href.split('?')[1].split('=');
        var secret = "";
        if (args[0] == "restart") {
            secret = args[1];
        }

        var pollTimer;

        var baseUrl = window.location.href.substr(0, window.location.href.indexOf("?")).replace("/wait", "");
        $.ajax(baseUrl + "/restart", {
            data: {
                token: secret,
            },
            timeout: 3000
        })
        .done(function(data) {
            clearInterval(pollTimer);
            window.location.href = baseUrl + "/setup";
        })
        .fail(function(xhr, status, err) {
            if (err === "timeout") {
                // Assume that the restart was initiated... Wait for server to be available again.
                var ctr = 0;
                pollTimer = setInterval(pollServer, 3000);
                pollServer();

                function pollServer() {
                    if (ctr > 59) {
                        clearInterval(pollTimer);
                        $("img#restart-spinner").parent().text("timeout").addClass("error");
                    } else {
                        $.ajax(baseUrl + "/setup", {
                            timeout: 2500
                        })
                        .done(function(data) {
                            clearInterval(pollTimer);
                            window.location.href = baseUrl + "/setup";
                        })
                        .fail(function(xhr, status, err) {
                            ctr++;
                        });
                    }
                }

            } else {
                clearInterval(pollTimer);
                $("img#restart-spinner").parent().text(err).addClass("error");
            }
        });

        return false;
    });

    if ( $("img#wrapup-spinner").length ) {
        var targetUrl = window.location.href.replace("/setup", "/final");
        var ctr = 0;
        var pollTimer = setInterval(pollServer, 3000);
        pollServer();

        function pollServer() {
            if (ctr > 20) {
                clearInterval(pollTimer);
                $("img#wrapup-spinner").parent().text("timeout").addClass("error");
            } else {
                $.ajax(targetUrl, {
                    timeout: 2500
                })
                .done(function(data) {
                    clearInterval(pollTimer);
                    window.location.href = targetUrl;
                })
                .fail(function(xhr, status, err) {
                    ctr++;
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

    $(document).ready(function() {
        if ( $(".datatable").length ) {
            var options = {
                pageLength: 25,
            };

            if ( $('.orders_list').length || $('.rel_orders_list').length ) {
                options["columnDefs"] = [ {
                        targets: 3,
                        render: $.fn.dataTable.render.ellipsis(15)
                    } ];
            }

            if ( $('.authz_list').length || $('.rel_authz_list').length ) {
                options["columnDefs"] = [
                    {
                        targets: 0,
                        render: $.fn.dataTable.render.ellipsis(15)
                    },
                    {
                        targets: 1,
                        render: $.fn.dataTable.render.ellipsis(40)
                    },
                    ];
            }

            if ( $('.challenges_list').length || $('.rel_challenges_list').length ) {
                options["columnDefs"] = [
                    {
                        targets: 1,
                        render: $.fn.dataTable.render.ellipsis(15)
                    },
                    {
                        targets: 5,
                        render: $.fn.dataTable.render.ellipsis(15)
                    },
                    {
                        targets: 6,
                        visible: false
                    },
                    ];
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
                window.location = window.location + '/../../certificates/' + data[0]
            });

            $(".datatable").on('draw.dt', positionFooter);
        }

        setTimeout(function() {
            $(window).resize();
        }, 10);
    });
});
