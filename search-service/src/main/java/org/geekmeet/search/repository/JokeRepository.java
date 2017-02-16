package org.geekmeet.search.repository;

import org.geekmeet.search.domain.Joke;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;

public interface JokeRepository extends ElasticsearchRepository<Joke, String> {

}
