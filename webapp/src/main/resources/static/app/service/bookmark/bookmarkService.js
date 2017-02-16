'use strict';

angular.module('webapp').factory('BookmarkService', ['$http', '$rootScope', 'GATEWAY', '$resource', function ($http, $rootScope, GATEWAY, $resource) {

    var BookmarkService = {};


    BookmarkService.addBookmark = function (joke, successCallback) {
        $resource(GATEWAY + '/bookmark/:documentId', {
            documentId: '@documentId'
        }, {
            update: {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + $rootScope.accessToken
                }
            }
        }).update({documentId: joke.documentId}, function (response) {
            successCallback(response);
        });
    };

    BookmarkService.removeBookmark = function (joke, successCallback) {
        $resource(GATEWAY + '/bookmark/:documentId', {
            documentId: '@documentId'
        }, {
            update: {
                method: 'DELETE',
                headers: {
                    'Authorization': 'Bearer ' + $rootScope.accessToken
                }
            }
        }).update({documentId: joke.documentId}, function (response) {
            successCallback(response);
        });
    };

    return BookmarkService;

}]);
