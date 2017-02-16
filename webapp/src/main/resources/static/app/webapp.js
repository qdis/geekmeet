'use strict';

angular
    .module('webapp', [
        'ngAnimate',
        'ngAria',
        'ngRoute',
        'ngSanitize',
        'ngMaterial',
        'md.data.table',
        'oc.lazyLoad',
        'ui.router',
        'ngResource',
        'ngMessages',
        'lfNgMdFileInput',
        'pascalprecht.translate'
    ]).constant("GATEWAY", "http://geekmeet.app").config(['$httpProvider', '$stateProvider', '$urlRouterProvider', '$ocLazyLoadProvider', '$mdThemingProvider',
    function ($httpProvider, $stateProvider, $urlRouterProvider, $ocLazyLoadProvider, $mdThemingProvider) {

        $httpProvider.defaults.headers.common["X-Requested-With"] = 'XMLHttpRequest';
        $httpProvider.defaults.xsrfCookieName = 'XSRF-TOKEN';
        $httpProvider.defaults.xsrfHeaderName = 'X-XSRF-TOKEN';
        $httpProvider.defaults.useXDomain = true;

        $ocLazyLoadProvider.config({
            debug: false,
            events: true
        });

        $urlRouterProvider.otherwise(function ($injector) {
            var $state = $injector.get('$state');
            $state.go('main.login');
        });

        $stateProvider
            .state('main', {
                url: '/main',
                templateUrl: 'app/views/main.html',
                resolve: {
                    loadMyFiles: function ($ocLazyLoad) {
                        return $ocLazyLoad.load(
                            {
                                files: [
                                    'app/controller/util/authenticationController.js',
                                    'app/service/authentication/authenticationService.js'
                                ]
                            })
                    }
                }
            })
            .state('main.admin', {
                url: '/admin',
                controller: 'AdminController as admin',
                templateUrl: 'app/views/parts/admin.html',
                resolve: {
                    loadMyFiles: function ($ocLazyLoad) {
                        return $ocLazyLoad.load({
                            files: [
                                'app/controller/admin/adminController.js',
                                'app/service/admin/adminService.js'
                            ]
                        })
                    }
                }
            })
            .state('main.home', {
                url: '/home',
                controller: 'HomeController as home',
                templateUrl: 'app/views/parts/home.html',
                resolve: {
                    loadMyFiles: function ($ocLazyLoad) {
                        return $ocLazyLoad.load({
                            files: [
                                'app/controller/home/homeController.js',
                                'app/service/search/searchService.js',
                                'app/service/admin/adminService.js',
                                'app/service/bookmark/bookmarkService.js'
                            ]
                        })
                    }
                }
            })
            .state('main.login', {
                url: '/login',
                templateUrl: 'app/views/parts/login.html',
                controller: 'LoginController as login',
                resolve: {
                    loadMyFiles: function ($ocLazyLoad) {
                        return $ocLazyLoad.load({
                            files: [
                                'app/controller/login/loginController.js'
                            ]
                        })
                    }
                }
            });


    }]).config(['$httpProvider',
    function ($httpProvider) {

        //TODO
    }]).config(['$locationProvider', function ($locationProvider) {
}]).service('APIInterceptor', ['$window', function ($window) {


    var service = this;

    // service.request = function (config) {
    //     if ($window.localStorage.getItem('ACCESS_TOKEN')) {
    //         config.headers['Authorization'] = $window.localStorage.getItem('ACCESS_TOKEN');
    //     }
    //     return config;
    // };

}]);





