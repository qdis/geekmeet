package org.geekmeet.search.client;

import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.Set;

@FeignClient(name = "bookmark-service")
public interface BookmarkServiceClient {

	@RequestMapping(method = RequestMethod.GET, value = "/bookmark/mine",
			consumes = MediaType.APPLICATION_JSON_UTF8_VALUE)
	Set<String> getMyBookmarks();

}
