'use strict';

angular.module('webapp').controller('HomeController', ['$scope', '$rootScope', 'GATEWAY', 'SearchService', 'BookmarkService', 'AdminService',
    function ($scope, $rootScope, GATEWAY, SearchService, BookmarkService, AdminService) {

        var home = this;

        home.user = $rootScope.user;
        home.data = {
            query: {
                pageSize: 10,
                page: 1,
                sortColumn: '-date',
                searchQuery: '',
                bookmarked: false
            },
            response: {},
            currentUser: $rootScope
        };


        home.doSearch = function () {
            var queryCopy = angular.copy(home.data.query);
            queryCopy.page -= 1;
            home.data.promise = SearchService.getJokes(queryCopy, function (response) {
                home.data.response = response;
            });
        };

        home.vote = function (joke, type) {
            SearchService.vote(joke.documentId, type, function () {
                if (type == 'UP') {
                    joke.upVoteCount += 1;
                    joke.upVoteUserIds.push(home.user.username);
                }
                if (type == 'DOWN') {
                    joke.downVoteCount += 1;
                    joke.downVoteUserIds.push(home.user.username);
                }
            })
        };

        home.bookmark = function (joke) {
            if (joke.bookmarked) {
                BookmarkService.removeBookmark(joke, function () {
                    joke.bookmarked = false;
                });
            } else {
                BookmarkService.addBookmark(joke, function () {
                    joke.bookmarked = true;
                });
            }
        };

        home.deleteJoke = function (joke) {
            AdminService.deleteJoke(joke.documentId, function () {
                home.doSearch();
            });
        };

        $scope.searchString = '';

        $scope.$watch('searchString', function (tmpStr) {
            // if searchStr is still the same..
            // go ahead and retrieve the data
            if (tmpStr === $scope.searchString) {
                home.data.query.searchQuery = tmpStr;
                home.doSearch();
            }
        });

        home.doSearch();


    }]);
