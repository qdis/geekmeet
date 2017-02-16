'use strict';

angular.module('webapp').controller('LoginController', ['$state', '$http', '$rootScope', '$window', '$interval', 'GATEWAY','AuthenticationService',
    function ($state, $http, $rootScope, $window, $interval, GATEWAY, AuthenticationService) {

    var login = this;

    login.credentials = {};

    login.facebook = function () {
        var windowOpened = $window.open(GATEWAY + '/authorization/login/facebook', 'Authenticate', 'width=1000,height=500,location=no,toolbar=no,menubar=no,scrollbars=yes,resizable=yes');

        windowOpened.onbeforeunload = function () {
            $state.go("main.home");
        };

    };

    login.google = function () {
        var windowOpened = $window.open(GATEWAY + '/authorization/login/google', 'Authenticate', 'width=1000,height=500,location=no,toolbar=no,menubar=no,scrollbars=yes,resizable=yes');

        windowOpened.onbeforeunload = function () {
            $state.go("main.home");
        };

    };

    login.withCredentials = function () {

        var req = {
            method: 'POST',
            url: GATEWAY + '/authorization/oauth/token',
            headers: {
                'Authorization': "Basic " + window.btoa('authorization-server:authorization-server-secret'),
                "Content-Type": "application/x-www-form-urlencoded"
            },
            transformRequest: function (obj) {
                var str = [];
                for (var p in obj)
                    str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
                return str.join("&");
            },
            data: {
                grant_type: "password",
                username: login.credentials.username,
                password: login.credentials.password
            }
        };

        $http(req).success(function (response) {

            console.log('response is ',response);

            $http.get(GATEWAY + "/authorization/me?access_token=" + response.access_token).success(function (data) {
                console.log(data);
                if (data.username) {
                    $window.localStorage.setItem("ACCESS_TOKEN", response.access_token);
                    $window.localStorage.setItem("ME", JSON.stringify(data));
                    AuthenticationService.checkUserLoggedIn(true);
                }
            }).error(function () {
            });

        }).error(function (data) {
        });

    };

}]);
