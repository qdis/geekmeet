package org.geekmeet.search.controller;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.geekmeet.search.client.BookmarkServiceClient;
import org.geekmeet.search.domain.Joke;
import org.geekmeet.search.domain.VoteType;
import org.geekmeet.search.repository.JokeRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.DigestUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/search")
public class SearchController {


	private final static Logger LOGGER = LoggerFactory.getLogger(SearchController.class);

	@Autowired
	private BookmarkServiceClient bookmarkServiceClient;

	@Autowired
	private JokeRepository jokeRepository;

	@PreAuthorize("hasRole('ADMIN')")
	@RequestMapping(method = RequestMethod.POST, path = "/upload")
	public ResponseEntity<Void> uploadJokes(@RequestBody List<String> jokes) {

		List<Joke> jokesToPersist = new ArrayList<>();
		Date now = new Date();
		for (String joke : jokes) {
			jokesToPersist.add(new Joke(DigestUtils.md5DigestAsHex(joke.getBytes()), joke, now));
		}

		jokeRepository.save(jokesToPersist);

		return new ResponseEntity<>(HttpStatus.OK);
	}

	@PreAuthorize("hasRole('ADMIN')")
	@RequestMapping(method = RequestMethod.DELETE, path = "/{documentId}")
	public ResponseEntity<Void> deleteJoke(@PathVariable String documentId) {
		jokeRepository.delete(documentId);

		return new ResponseEntity<>(HttpStatus.OK);
	}

	@RequestMapping(method = RequestMethod.POST, path = "/{documentId}/vote")
	public ResponseEntity<Void> vote(@PathVariable String documentId, @RequestParam VoteType voteType,
			Principal principal) {

		Joke joke = jokeRepository.findOne(documentId);
		switch (voteType) {
		case UP:
			joke.getUpVoteUserIds().add(principal.getName());
			break;
		case DOWN:
			joke.getDownVoteUserIds().add(principal.getName());
			break;
		}
		jokeRepository.save(joke);

		return new ResponseEntity<>(HttpStatus.OK);
	}

	@RequestMapping(method = RequestMethod.GET, path = "/find")
	public ResponseEntity<CustomPage> listDeletedFiles(
			@RequestParam(required = false, defaultValue = "") String searchQuery,
			@RequestParam(value = "bookmarked", defaultValue = "false") boolean bookmarked,
			@RequestParam(value = "pageSize", defaultValue = "10") int pageSize,
			@RequestParam(value = "page", defaultValue = "0") int page,
			@RequestParam(value = "sortColumn", defaultValue = "-date") String sortColumn) {

		Set<String> bookmarks = bookmarkServiceClient.getMyBookmarks();

		LOGGER.info("Bookmarks are : "+bookmarks);

		QueryBuilder queryBuilder;
		if (bookmarked) {
			queryBuilder = QueryBuilders.andQuery(StringUtils.isEmpty(searchQuery) ?
							QueryBuilders.queryStringQuery("*") :
							QueryBuilders.matchPhrasePrefixQuery("joke", searchQuery),
					QueryBuilders.termsQuery("documentId", bookmarks));
		} else {
			queryBuilder = StringUtils.isEmpty(searchQuery) ?
					QueryBuilders.queryStringQuery("*") :
					QueryBuilders.matchPhrasePrefixQuery("joke", searchQuery);
		}
		Page<Joke> response = jokeRepository.search(queryBuilder, new PageRequest(page, pageSize,
				new Sort(sortColumn.startsWith("-") ? Sort.Direction.DESC : Sort.Direction.ASC,
						sortColumn.startsWith("-") ? sortColumn.substring(1) : sortColumn)));

		for (Joke joke : response.getContent()) {
			if (bookmarks.contains(joke.getDocumentId())) {
				joke.setBookmarked(true);
			}
		}
		return new ResponseEntity<>(new CustomPage(response.getTotalElements(), response.getContent()), HttpStatus.OK);
	}

	// Yeah, fuck this shit and their Release Trains
	@Data
	@ToString
	@AllArgsConstructor
	@NoArgsConstructor
	public static class CustomPage {

		private long totalElements;
		private List<Joke> content;
	}
}
