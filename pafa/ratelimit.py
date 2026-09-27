import time
import functools
import re

def with_ratelimit(max_retries=5, base_wait=10.0):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    error_str = str(e).lower()
                    if "429" in error_str or "rate_limit" in error_str:
                        # Try to parse "try again in 9.78s"
                        match = re.search(r"try again in ([\d\.]+)s", error_str)
                        if match:
                            wait_time = float(match.group(1)) + 1.0
                        else:
                            wait_time = base_wait * (2 ** retries)
                            
                        print(f"Rate limited. Waiting {wait_time:.2f}s before retry (Attempt {retries+1}/{max_retries})...")
                        time.sleep(wait_time)
                        retries += 1
                    else:
                        raise e
            raise Exception("Max retries exceeded for rate limited endpoint.")
        return wrapper
    return decorator
