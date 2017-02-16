package org.geekmeet.bookmark.controller;

import org.geekmeet.bookmark.domain.Bookmark;
import org.geekmeet.bookmark.repository.BookmarkRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/bookmark")
public class BookmarkController {

	private final static Logger LOGGER = LoggerFactory.getLogger(BookmarkController.class);

	@Autowired
	private BookmarkRepository bookmarkRepository;

	@RequestMapping(method = RequestMethod.POST, path = "/{documentId}")
	@CacheEvict(cacheNames = "bookmarks", key = "#principal.name")
	public ResponseEntity<Void> addBookmark(Principal principal, @PathVariable String documentId) {
		bookmarkRepository.save(new Bookmark(new Bookmark.BookmarkKey(principal.getName(), documentId)));
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@RequestMapping(method = RequestMethod.DELETE, path = "/{documentId}")
	@CacheEvict(cacheNames = "bookmarks", key = "#principal.name")
	public ResponseEntity<Object> deleteBookmark(Principal principal, @PathVariable String documentId) {
		bookmarkRepository.delete(new Bookmark.BookmarkKey(principal.getName(), documentId));
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@RequestMapping(method = RequestMethod.GET, path = "/mine")
	@Cacheable(cacheNames = "bookmarks", key = "#principal.name")
	public ResponseEntity<List<String>> getBookmarkedDocuments(Principal principal) {
		return new ResponseEntity<>(bookmarkRepository.findByUsername(principal.getName()).stream()
				.map(b -> b.getBookmarkKey().getDocumentId()).collect(Collectors.toList()), HttpStatus.OK);
	}

	@PreAuthorize(value = "hasRole('ADMIN')")
	@RequestMapping(method = RequestMethod.DELETE, path = "/obsolete/{documentId}")
	@CacheEvict(cacheNames = "bookmarks")
	@Transactional
	public ResponseEntity<Object> removeObsoleteBookmark(@PathVariable String documentId) {
		bookmarkRepository.deleteByDocumentId(documentId);
		return new ResponseEntity<>(HttpStatus.OK);
	}

}
