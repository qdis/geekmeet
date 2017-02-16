package org.geekmeet.admin.rest;

import org.geekmeet.admin.client.BookmarkServiceClient;
import org.geekmeet.admin.client.SearchServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class ManagementController {

	@Autowired
	private BookmarkServiceClient bookmarkServiceClient;

	@Autowired
	private SearchServiceClient searchServiceClient;

	@PreAuthorize(value = "hasRole('ADMIN')")
	@RequestMapping(value = "/joke/{documentId}", method = RequestMethod.DELETE)
	public ResponseEntity<Void> delete(@PathVariable String documentId) {
		searchServiceClient.deleteJoke(documentId);
		bookmarkServiceClient.deleteObsolete(documentId);
		return new ResponseEntity<>(HttpStatus.ACCEPTED);

	}

}
