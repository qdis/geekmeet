'use strict';

angular.module('webapp').factory('AuthenticationService', ['$state', '$http', '$rootScope', '$window', '$location', 'GATEWAY', function ($state, $http, $rootScope, $window, $location, GATEWAY) {

    var AuthenticationService = {};

    AuthenticationService.isLogin = function () {
        return $state.current.name == 'main.login';
    };

    AuthenticationService.checkAuthentication = function () {

        var search = $window.location.search;
        if (search.indexOf('?access_token=') == 0) {
            var token = search.substring('?access_token='.length);

            $http({
                method: 'GET',
                url: GATEWAY + '/authorization/me?access_token=' + token,
                headers: {
                    'Authorization': "Bearer " + token
                }
            }).success(function (data) {
                $window.localStorage.setItem("ACCESS_TOKEN", token);
                $window.localStorage.setItem("ME", JSON.stringify(data));
                $window.close();
            }).error(function () {
                AuthenticationService.checkUserLoggedIn();
            });

        } else {
            AuthenticationService.checkUserLoggedIn();
        }

    };

    AuthenticationService.logout = function () {
        $window.localStorage.removeItem("ACCESS_TOKEN");
        $window.localStorage.removeItem("ME");
        $http.get(GATEWAY + '/authorization/logout').success(function (data) {
            console.log(data);
        }).error(function (data) {
            console.log(data);
        });
        $state.go('main.login');
    };

    AuthenticationService.checkUserLoggedIn = function (shouldRedirectAdmin) {
        try {
            var me = JSON.parse($window.localStorage.getItem("ME"));
            var isUser = false;
            var isAdmin = false;
            console.log(me);
            angular.forEach(me.authorities, function (authority) {
                if (authority.authority == 'ROLE_USER') {
                    isUser = true;
                }
                if (authority.authority == 'ROLE_ADMIN') {
                    isAdmin = true;
                }
            });
            $rootScope.accessToken = $window.localStorage.getItem("ACCESS_TOKEN");
            $rootScope.user = me;
            $rootScope.user.isAdmin = isAdmin;
            $rootScope.user.isUser = isUser;
            if (isAdmin) {
                if (shouldRedirectAdmin) {
                    $state.go('main.admin');
                }
            } else if (isUser) {
                $state.go('main.home');
            } else {
                $state.go('main.login');
            }
        } catch (e) {
            $state.go('main.login');
        }
        return false;
    };

    return AuthenticationService;

}]);
