package org.geekmeet.admin.client;

import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@FeignClient(name = "bookmark-service")
public interface BookmarkServiceClient {

	@RequestMapping(method = RequestMethod.DELETE, value = "/bookmark/obsolete/{documentId}",
			consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
	void deleteObsolete(@PathVariable("documentId") String documentId);

}
