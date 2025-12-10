<!DOCTYPE html>
<html lang="en" class="no-js">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1, user-scalable=0">
        <meta name="robots" content="noindex">
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="backend-base-path" content="/backend">
        <meta name="csrf-token" content="<?= $xsrf; ?>">
        <link rel="icon" type="image/png" href="/modules/backend/assets/images/favicon.png">
        <title>Administration Area</title>
        <link href="/modules/system/assets/ui/storm.css?v=1" rel="stylesheet" importance="high">
        <link href="/modules/system/assets/ui/storm.css?v=1" rel="preload" as="style" importance="high">
        <link href="/modules/system/assets/ui/icons.css?v=1" rel="stylesheet" importance="high">
        <link href="/modules/system/assets/ui/icons.css?v=1" rel="preload" as="style" importance="high">
        <link href="/modules/backend/assets/css/winter.css?v=1" rel="stylesheet" importance="high">
        <link href="/modules/backend/assets/css/winter.css?v=1" rel="preload" as="style" importance="high">
    
        <script>
            "use strict";
            /* Only run on HTTPS connections
            * Block off Front-end Service Worker from running in the Backend allowing security injections, see GitHub #4384
            */
            if (location.protocol === 'https:') {
                // Unregister all service workers before signing in to prevent cache issues, see github issue: #3707
                navigator.serviceWorker.getRegistrations().then(
                    function (registrations) {
                        registrations.forEach(function (registration) {
                            registration.unregister();
                        });
                    }
                );
            }
        </script>

        <style>
            #layout-canvas .flash-message.fade {
                display:block;
                opacity:1;
            }
            body.outer .layout > .layout-row > .layout-cell .outer-form-container {
                /* Larger inputs in laptop mode */
                width: 650px
            }
            @media (max-width: 768px) {
                /* Larger inputs in mobile mode */
                body.outer .layout > .layout-row > .layout-cell .outer-form-container {
                    width: 382px;
                }
                body.outer .layout > .layout-row > .layout-cell .outer-form-container .horizontal-form button {
                    width: 100%!important;
                }
            }
        </style>
    </head>

    <body class="outer signin preload">
        <div id="layout-canvas">
            <div class="layout">
                <div class="layout-row min-size layout-head">
                    <div class="layout-cell">
                        <h1>Secure System | نظام آمن | Sîstema Ewle</h1>
                    </div>
                </div>

                <div class="layout-row">
                    <div class="layout-cell">
                        <div class="outer-form-container">
                            <?= Form::open(['url' => '/backend/backend/auth/signin']) ?>
                                <input type="hidden" name="postback" value="1" />

                                <div class="form-elements" role="form">
                                    <div class="form-group text-field horizontal-form">

                                        <!-- Login -->
                                        <input
                                            type="text"
                                            name="login"
                                            value=""
                                            class="form-control icon user"
                                            placeholder="Username | Nav | اسم المستخدم"
                                            autocomplete="off"
                                        />

                                        <!-- Password -->
                                        <input
                                            type="password"
                                            name="password"
                                            value=""
                                            class="form-control icon lock"
                                            placeholder="كلمة المرور | Şîfre | Password"
                                            autocomplete="off"
                                        />

                                        <!-- Submit Login -->
                                        <button type="submit" class="btn btn-primary login-button">
                                            تسجيل الدخول 
                                            | Têketin 
                                            | Login
                                        </button>
                                    </div>

                                    
                                    <p class="wn-icon-lock pull-right forgot-password">
                                        <!-- Forgot your password? -->
                                        <a name="/backend/backend/auth/restore" class="text-muted">
                                            نسيت كلمة السر؟ 
                                            | Şîfreya xwe ji bîr kir? 
                                            | Forgot your password?<br/>
                                            Please talk with a Systems Administrator.
                                            | Ji kerema xwe bi rêveberekî sîsteman re bipeyivin.
                                            | يرجى التحدث مع مسؤول النظام.
                                        </a>
                                    </p>
                                </div>
                            <?= Form::close() ?>
                        </div>

                        <!-- Flash Messages -->
                        <div id="layout-flash-messages">
                            <?php if ($exceptionMessage): ?>
                                <p class="flash-message fade error" data-interval="5">
                                    <?= substr(preg_replace('#/var/www/.*|[(]?SQL:.*#', '', $exceptionMessage), 0, 500); ?>.
                                    <button type="button" class="close" aria-hidden="true">×</button>
                                </p>
                            <?php endif ?>            
                        </div>
                
                    </div>
                </div>
            </div>
        </div>
    </body>
</html>
