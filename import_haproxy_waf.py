import os
import subprocess
import logging
from pathlib import Path
import shutil
import filecmp
import time

# --- Configuration ---
LOG_LEVEL = logging.INFO  # DEBUG, INFO, WARNING, ERROR
WAF_DIR = Path(os.getenv("WAF_DIR", "waf_patterns/haproxy")).resolve()
HAPROXY_WAF_DIR = Path(os.getenv("HAPROXY_WAF_DIR", "/etc/haproxy/waf/")).resolve()
HAPROXY_CONF = Path(os.getenv("HAPROXY_CONF", "/etc/haproxy/haproxy.cfg")).resolve()
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/etc/haproxy/waf_backup/")).resolve()

# HAProxy WAF configuration snippet
WAF_CONFIG_SNIPPET = """
# WAF and Bot Protection (Generated by import_haproxy_waf.py)
frontend http-in
    bind *:80
    mode http
    option httplog
    # WAF and Bot Protection ACLs and Rules
    # Include generated ACL files
    include /etc/haproxy/waf/*.acl
"""
# --- Logging Setup ---
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)



def copy_waf_files():
    """Copies WAF files, handling existing files, creating backups."""
    logger.info("Copying HAProxy WAF patterns...")

    HAPROXY_WAF_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)  # Ensure backup dir exists

    for acl_file in WAF_DIR.glob("*.acl"):  # Find all .acl files
        dst_path = HAPROXY_WAF_DIR / acl_file.name

        try:
            if dst_path.exists():
                # Compare and backup if different
                if filecmp.cmp(acl_file, dst_path, shallow=False):
                    logger.info(f"Skipping {acl_file.name} (identical file exists).")
                    continue
                # Different file exists: backup
                backup_path = BACKUP_DIR / f"{dst_path.name}.{int(time.time())}"
                logger.warning(f"Existing {dst_path.name} differs. Backing up to {backup_path}")
                shutil.copy2(dst_path, backup_path)  # Backup old file

            # Copy the (new or updated) file
            shutil.copy2(acl_file, dst_path)
            logger.info(f"Copied {acl_file.name} to {dst_path}")

        except OSError as e:
            logger.error(f"Error copying {acl_file.name}: {e}")
            raise


def update_haproxy_conf():
    """Ensures the include statement is in haproxy.cfg, avoiding duplicates."""
    logger.info("Checking HAProxy configuration for WAF include...")

    try:
        with open(HAPROXY_CONF, "r") as f:
            config_lines = f.readlines()

        # Check if the *exact* snippet is already present.  We'll check for the
        # key parts of the snippet to be more robust.
        snippet_present = False
        for line in config_lines:
            if "include /etc/haproxy/waf/*.acl" in line:
                snippet_present = True
                break

        if not snippet_present:
             # Find the 'frontend http-in' section
            frontend_start = -1
            for i, line in enumerate(config_lines):
                if line.strip().startswith("frontend http-in"):
                    frontend_start = i
                    break

            if frontend_start == -1:
                logger.warning("No 'frontend http-in' section found. Appending to end of file.")
                with open(HAPROXY_CONF, "a") as f:
                    f.write(f"\n{WAF_CONFIG_SNIPPET}\n")
                logger.info(f"Added WAF configuration snippet to {HAPROXY_CONF}")
            else:
                # Find the end of the 'frontend http-in' section
                frontend_end = -1
                for i in range(frontend_start + 1, len(config_lines)):
                    if line.strip() == "" or  not line.startswith("    "): # Check it is part of the config
                         frontend_end = i
                         break


                if frontend_end == -1:
                    frontend_end = len(config_lines)  # End of file

                # Insert the include statement *within* the frontend section.
                config_lines.insert(frontend_end, "    include /etc/haproxy/waf/*.acl\n")

                # Write the modified configuration back to the file
                with open(HAPROXY_CONF, "w") as f:
                    f.writelines(config_lines)
                logger.info(f"Added WAF include to 'frontend http-in' section in {HAPROXY_CONF}")
        else:
            logger.info("WAF include statement already present.")

    except FileNotFoundError:
        logger.error(f"HAProxy configuration file not found: {HAPROXY_CONF}")
        raise
    except OSError as e:
        logger.error(f"Error updating HAProxy configuration: {e}")
        raise


def reload_haproxy():
    """Tests the HAProxy configuration and reloads if valid."""
    logger.info("Reloading HAProxy...")

    try:
        # Test configuration
        result = subprocess.run(["haproxy", "-c", "-f", str(HAPROXY_CONF)],
                                capture_output=True, text=True, check=True)
        logger.info(f"HAProxy configuration test successful:\n{result.stdout}")


        # Reload HAProxy
        result = subprocess.run(["systemctl", "reload", "haproxy"],
                                capture_output=True, text=True, check=True)
        logger.info("HAProxy reloaded.")


    except subprocess.CalledProcessError as e:
        logger.error(f"HAProxy command failed: {e.cmd} - Return code: {e.returncode}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        raise  # Re-raise to signal failure
    except FileNotFoundError:
        logger.error("'haproxy' or 'systemctl' command not found. Is HAProxy/systemd installed?")
        raise


def main():
    """Main function."""
    try:
        copy_waf_files()
        update_haproxy_conf()
        reload_haproxy()
        logger.info("HAProxy WAF configuration updated successfully.")
    except Exception as e:
        logger.critical(f"Script failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
