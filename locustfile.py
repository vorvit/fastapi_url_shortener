from locust import HttpUser, task, between

class WebsiteUser(HttpUser):
    wait_time = between(1, 5)

    short_code = "ZJmaf6"

    @task
    def redirect_with_cache(self):
        """Test redirect with caching enabled"""
        self.client.get(f"/{self.short_code}")

    @task
    def redirect_without_cache(self):
        """Test redirect bypassing the cache"""
        self.client.get(f"/{self.short_code}?nocache=true")