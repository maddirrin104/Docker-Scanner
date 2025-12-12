import json
import os
from datetime import datetime, timedelta
from caching_result.db import get_db_connection
from caching_result.image_helper import get_image_digest, get_cache_key


class CacheManager:
    def __init__(self, cache_expire_hours=24):
        self.cache_expire_hours = cache_expire_hours

    @staticmethod
    def normalize_severity(severity_list):
        """Ensure deterministic severity key for caching."""
        if not severity_list:
            return "[]"
        return json.dumps(sorted(severity_list))  # ensure sorted order

    def get_cached_report(self, image_name, severity_filter=None, fail_threshold=0, fail_severity=""):
        conn = get_db_connection()
        c = conn.cursor()

        cache_key = get_cache_key(image_name)
        if not cache_key:
            conn.close()
            return None, False

        sev_norm = self.normalize_severity(severity_filter)

        c.execute("""
            SELECT report_path, scan_time
            FROM scan_cache
            WHERE image_name = ?
              AND trivy_output_hash = ?
              AND severity_filter = ?
              AND fail_threshold = ?
              AND fail_severity = ?
            ORDER BY scan_time DESC
            LIMIT 1
        """, (image_name, cache_key, sev_norm, fail_threshold, fail_severity))

        row = c.fetchone()
        conn.close()

        if not row:
            return None, False

        scan_time = datetime.fromisoformat(row["scan_time"])
        if datetime.now() - scan_time > timedelta(hours=self.cache_expire_hours):
            print(f"Cache expired for {image_name}")
            return None, False

        report_path = row["report_path"]

        if not os.path.exists(report_path):
            print(f"Cache file removed: {report_path}")
            return None, False

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                return json.load(f), True
        except Exception as e:
            print(f"Failed to load cache file: {e}")
            return None, False

    def save_cache(self, image_name, report_list, report_path,
                   severity_filter=None, fail_threshold=0, fail_severity=""):

        conn = get_db_connection()
        c = conn.cursor()

        digest = get_image_digest(image_name)
        cache_key = get_cache_key(image_name)

        if not cache_key:
            print("Cannot save cache: missing digest or DB timestamp")
            conn.close()
            return False

        sev_norm = self.normalize_severity(severity_filter)

        try:
            c.execute("""
                INSERT OR REPLACE INTO scan_cache
                (image_name, image_digest, trivy_output_hash, report_path,
                 severity_filter, fail_threshold, fail_severity, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (image_name, digest, cache_key, report_path,
                  sev_norm, fail_threshold, fail_severity))

            conn.commit()
            print(f"Saved cache for {image_name} (digest={digest[:12]})")
            return True
        except Exception as e:
            print(f"Error saving cache: {e}")
            return False
        finally:
            conn.close()

    def clear_cache_for_image(self, image_name):
        conn = get_db_connection()
        c = conn.cursor()

        c.execute("DELETE FROM scan_cache WHERE image_name = ?", (image_name,))
        conn.commit()
        conn.close()
        print(f"Cleared cache for {image_name}")

    def clear_all_cache(self):
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM scan_cache")
        conn.commit()
        conn.close()
        print("Cleared ALL cache")
