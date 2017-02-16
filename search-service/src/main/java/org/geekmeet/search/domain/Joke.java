package org.geekmeet.search.domain;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldIndex;
import org.springframework.data.elasticsearch.annotations.FieldType;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Data
@ToString
@Document(indexName = Joke.INDEX_NAME)
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(of = { "documentId" })
public class Joke {

	public final static String INDEX_NAME = "joke";

	@Id
	private String documentId;

	@Field(type = FieldType.String, store = true, index = FieldIndex.analyzed)
	private String joke;

	@Field(type = FieldType.Date, store = true, index = FieldIndex.not_analyzed)
	private Date date;

	@Field(type = FieldType.String, store = true, index = FieldIndex.not_analyzed)
	private Set<String> upVoteUserIds;

	@Field(type = FieldType.String, store = true, index = FieldIndex.not_analyzed)
	private Set<String> downVoteUserIds;

	@Field(type = FieldType.Long, store = true, index = FieldIndex.not_analyzed)
	private long upVoteCount;

	@Field(type = FieldType.Long, store = true, index = FieldIndex.not_analyzed)
	private long downVoteCount;

	@Transient
	private boolean bookmarked;

	public Joke(String documentId, String joke, Date date) {
		this.documentId = documentId;
		this.joke = joke;
		this.date = date;
	}

	public Set<String> getUpVoteUserIds() {
		if (upVoteUserIds == null) {
			upVoteUserIds = new HashSet<>();
		}
		return upVoteUserIds;
	}

	public Set<String> getDownVoteUserIds() {
		if (downVoteUserIds == null) {
			downVoteUserIds = new HashSet<>();
		}
		return downVoteUserIds;
	}

	public void setUpVoteUserIds(Set<String> upVoteUserIds) {
		this.upVoteUserIds = upVoteUserIds != null ? upVoteUserIds : new HashSet<>();
		this.upVoteCount = this.upVoteUserIds.size();
	}

	public void setDownVoteUserIds(Set<String> downVoteUserIds) {
		this.downVoteUserIds = downVoteUserIds != null ? downVoteUserIds : new HashSet<>();
		this.downVoteCount = this.downVoteUserIds.size();
	}

	public long getUpVoteCount() {
		this.upVoteCount = upVoteUserIds.size();
		return upVoteCount;
	}

	public long getDownVoteCount() {
		this.downVoteCount = downVoteUserIds.size();
		return downVoteCount;
	}

}
