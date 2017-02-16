package org.geekmeet.admin.rest;

import org.apache.commons.io.IOUtils;
import org.geekmeet.admin.client.SearchServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/admin")
public class ImportController {

	@Autowired
	private SearchServiceClient searchServiceClient;

	@PreAuthorize(value = "hasRole('ADMIN')")
	@RequestMapping(value = "/upload", method = RequestMethod.POST, consumes = { "multipart/form-data" })
	public ResponseEntity<Void> uploadFiles(@RequestParam("file") List<MultipartFile> files, Principal principal) {
		try {
			for(MultipartFile file : files){
				List<String> jokes = IOUtils.readLines(file.getInputStream(), "UTF-8");
				searchServiceClient.uploadJokes(jokes);
			}
		} catch (IOException e) {
			return new ResponseEntity<>(HttpStatus.CONFLICT);
		}
		return new ResponseEntity<>(HttpStatus.ACCEPTED);

	}

}
