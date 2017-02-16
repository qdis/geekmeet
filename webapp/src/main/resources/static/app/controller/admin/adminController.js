'use strict';

angular.module('webapp').controller('AdminController', ['$state', '$http', '$rootScope', '$window', '$interval', 'GATEWAY', 'AdminService', function ($state, $http, $rootScope, $window, $interval, GATEWAY, AdminService) {

    var admin = this;

    (function () {
        if (!$rootScope.user.isAdmin) {
            $state.go('main.home');
        }
    })();

    admin.uploadFiles = function () {
        admin.progress = 0;
        admin.uploadInProgress = true;
        var files = [];
        angular.forEach(admin.files, function (file) {
            files.push(file.lfFile);
        });
        AdminService.uploadFiles(files, function (uploadProgressEvent) {
            if (uploadProgressEvent.type === 'progress') {
                admin.progress = (uploadProgressEvent.loaded / uploadProgressEvent.total) * 100;
            }
        }, function () {
            console.log('upload complete');
            admin.progress = 0;
            admin.uploadInProgress = false;
        }, function () {
            console.log('upload failed');
            admin.progress = 0;
            admin.uploadInProgress = false;
        });
    }


}]);
