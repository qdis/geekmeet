'use strict';

angular.module('webapp').factory('AdminService', ['$http', '$rootScope', 'GATEWAY', '$resource', function ($http, $rootScope, GATEWAY, $resource) {

    var AdminService = {};

    AdminService.uploadFiles = function (files, progressCallback, successCallback, errorCallback) {
        $resource(GATEWAY + '/admin/upload', {}, {
            upload: {
                method: 'POST',
                transformRequest: function (data) {
                    var formData = new FormData();
                    angular.forEach(data.file, function (file) {
                        formData.append("file", file);
                    });
                    console.log(data);
                    console.log(formData);
                    return formData;
                },
                uploadEventHandlers: {
                    progress: function (event) {
                        if (progressCallback) {
                            progressCallback(event);
                        }
                    }
                },
                headers: {
                    'Content-Type': undefined,
                    'Authorization': 'Bearer ' + $rootScope.accessToken
                }
            }
        }).upload({file: files}, function (response) {
            if (successCallback) {
                successCallback(response);
            }
        }, function (error) {
            if (errorCallback) {
                errorCallback(error);
            }
        });
    };

    AdminService.deleteJoke = function (documentId, successCallback) {
        $resource(GATEWAY + '/admin/joke/:documentId', {
            documentId: '@documentId'
        }, {
            update: {
                method: 'DELETE',
                headers: {
                    'Authorization': 'Bearer ' + $rootScope.accessToken
                }
            }
        }).update({documentId: documentId}, function (response) {
            successCallback(response);
        });
    };

    return AdminService;

}]);
