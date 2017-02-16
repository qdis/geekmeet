'use strict';

angular.module('webapp').factory('SearchService', ['$http', '$rootScope', 'GATEWAY', '$resource', function ($http, $rootScope, GATEWAY, $resource) {

    var SearchService = {};

    SearchService.getJokes = function (query, successCallback) {
        return $resource(GATEWAY + '/search/find', {searchQuery: '@searchQuery'}, {
            search: {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer ' + $rootScope.accessToken
                }
            }
        }).search(query, function (response) {
            successCallback(response);
        }).$promise;
    };

    SearchService.vote = function (documentId, voteType, successCallback) {
        $resource(GATEWAY + '/search/:documentId/vote', {
            documentId: '@documentId',
            voteType: '@voteType'
        },{
            update: {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + $rootScope.accessToken
                }
            }
        }).update({documentId: documentId, voteType: voteType}, function (response) {
            successCallback(response);
        });
    };

    SearchService.bookmark = function (documentId, successCallback) {
        $resource(GATEWAY + '/bookmark/:documentId/vote', {
            documentId: '@documentId',
            voteType: '@voteType'
        },{
            update: {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + $rootScope.accessToken
                }
            }
        }).update({documentId: documentId, voteType: voteType}, function (response) {
            successCallback(response);
        });
    };

    return SearchService;

}
]);
