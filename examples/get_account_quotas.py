from spyse import Client
import os

api_token = os.getenv("SPYSE_API_TOKEN")
client = Client(api_token)

q = client.get_quotas()
    
print(f"Customer account quotas:")
print(f"Subscription period start at: {q.start_at}")
print(f"Subscription period end at: {q.end_at}")
print(f"API requests remaining: {q.api_requests_remaining}")
print(f"API requests limit: {q.api_requests_limit}")
print(f"Downloads remaining: {q.downloads_limit_remaining}")
print(f"Downloads limit: {q.downloads_limit}")
print(f"Is scroll search enabled: {q.is_scroll_search_enabled}")
print(f"Search params limit: {q.search_params_limit}")
