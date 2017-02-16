package org.geekmeet.bookmark.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.Embeddable;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import java.io.Serializable;

@Entity
@Data
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class Bookmark {

	@EmbeddedId
	private BookmarkKey bookmarkKey;

	@Data
	@ToString
	@AllArgsConstructor
	@NoArgsConstructor
	@Embeddable
	public static class BookmarkKey implements Serializable {
		public final static long serialVersionUID = 1l;

		private String username;

		private String documentId;

	}

}
