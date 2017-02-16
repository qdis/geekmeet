package org.geekmeet.admin.client;

import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@FeignClient(name = "search-service")
public interface SearchServiceClient {

	@RequestMapping(method = RequestMethod.POST, value = "/search/upload", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
	void uploadJokes(@RequestBody List<String> jokes);

	@RequestMapping(method = RequestMethod.DELETE, value = "/search/{documentId}", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
	void deleteJoke(@PathVariable("documentId") String documentId);

}
