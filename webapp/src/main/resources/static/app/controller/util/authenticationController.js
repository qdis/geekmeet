'use strict';

angular.module('webapp').controller('AuthenticationController', ['$state', 'AuthenticationService','$rootScope', function ($state, AuthenticationService, $rootScope) {

    var authentication = this;

    authentication.isLogin = function () {
        return AuthenticationService.isLogin();
    };

    authentication.checkAuthentication = function () {
        AuthenticationService.checkAuthentication();
    };

    authentication.logout = function () {
        AuthenticationService.logout();
    };

    authentication.isUserLoggedIn = function () {
        authentication.isAdmin = $rootScope.user.isAdmin;
        authentication.isUser = $rootScope.user.isUser;
        return authentication.isAdmin || authentication.isUser;
    };


}]);
