import json
import os
from datetime import datetime, timedelta
from caching_result.db import get_db_connection
from caching_result.image_helper import get_image_digest, hash_trivy_output

class CacheManager:
    def __init__(self, cache_expire_hours=24):
        self.cache_expire_hours = cache_expire_hours

    def get_cached_report(self, image_name, severity_filter=None, fail_threshold=0, fail_severity=""):
        """
        Check if cached report exists & is valid.
        Returns: (report_data, cache_hit) or (None, False) if not found/expired.
        """
        conn = get_db_connection()
        c = conn.cursor()

        # Get digest for this image
        digest = get_image_digest(image_name)
        if not digest:
            conn.close()
            return None, False

        # Query cache
        c.execute("""
        SELECT id, report_path, scan_time, severity_filter, fail_threshold, fail_severity
        FROM scan_cache
        WHERE image_digest = ? AND severity_filter = ? AND fail_threshold = ? AND fail_severity = ?
        ORDER BY scan_time DESC
        LIMIT 1
        """, (digest, json.dumps(severity_filter or []), fail_threshold, fail_severity or ""))

        row = c.fetchone()
        conn.close()

        if not row:
            return None, False

        # Check if expired
        scan_time = datetime.fromisoformat(row['scan_time'])
        if datetime.now() - scan_time > timedelta(hours=self.cache_expire_hours):
            print(f"Cache expired for {image_name} (scanned {scan_time})")
            return None, False

        # Load report from file
        report_path = row['report_path']
        if not os.path.exists(report_path):
            print(f"Cache file not found: {report_path}")
            return None, False

        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                report = json.load(f)
            print(f"Cache hit for {image_name} (scanned {scan_time})")
            return report, True
        except Exception as e:
            print(f"Error loading cached report: {e}")
            return None, False

    def save_cache(self, image_name, report_list, report_path, 
                   severity_filter=None, fail_threshold=0, fail_severity=""):
        """
        Save scan result to cache.
        """
        conn = get_db_connection()
        c = conn.cursor()

        digest = get_image_digest(image_name)
        if not digest:
            print("Cannot save cache: unable to get image digest")
            conn.close()
            return False

        try:
            report_json = json.dumps(report_list)
            output_hash = hash_trivy_output(report_json)

            c.execute("""
            INSERT OR REPLACE INTO scan_cache
            (image_name, image_digest, trivy_output_hash, report_path, severity_filter, fail_threshold, fail_severity, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (image_name, digest, output_hash, report_path, 
                  json.dumps(severity_filter or []), fail_threshold, fail_severity or ""))

            conn.commit()
            print(f"Cached scan result for {image_name} (digest: {digest[:12]}...)")
            return True
        except Exception as e:
            print(f"Error saving cache: {e}")
            return False
        finally:
            conn.close()

    def clear_cache_for_image(self, image_name):
        """
        Clear all cached entries for an image.
        """
        conn = get_db_connection()
        c = conn.cursor()

        digest = get_image_digest(image_name)
        if digest:
            c.execute("DELETE FROM scan_cache WHERE image_digest = ?", (digest,))
            conn.commit()
            print(f"Cleared cache for {image_name}")

        conn.close()

    def clear_all_cache(self):
        """
        Clear entire cache.
        """
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM scan_cache")
        conn.commit()
        conn.close()
        print("Cleared all cache")