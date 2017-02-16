package org.geekmeet.bookmark.repository;

import org.geekmeet.bookmark.domain.Bookmark;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface BookmarkRepository extends JpaRepository<Bookmark, Bookmark.BookmarkKey> {

	@Query("SELECT b FROM Bookmark b where b.bookmarkKey.username = ?1 ")
	List<Bookmark> findByUsername(String username);

	@Modifying
	@Query("DELETE FROM Bookmark b where b.bookmarkKey.documentId = ?1")
	void deleteByDocumentId(String documentId);

}
