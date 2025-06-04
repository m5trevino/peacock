from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, WebDriverException
import time

def scrape_codeshare_selenium(url):
    # Configure the Firefox WebDriver
    service = Service('/usr/local/bin/geckodriver')
    options = Options()
    options.add_argument('--headless')  # Run in headless mode (no GUI)
    
    print("Initializing the WebDriver...")
    try:
        driver = webdriver.Firefox(service=service, options=options)
        print("WebDriver initialized successfully.")
    except WebDriverException as e:
        print(f"Error initializing WebDriver: {e}")
        return None

    try:
        print(f"Navigating to {url}...")
        driver.get(url)
        time.sleep(5)  # Give the page time to load
        
        print("Attempting to locate the script code...")
        # Adjust the XPath or CSS selector to the actual structure of the page
        code_element = driver.find_element(By.XPATH, "//div[@id='editor']/div[2]")
        script_code = code_element.text
        print("Script code extracted successfully.")

        # Return the script code
        return script_code

    except NoSuchElementException:
        print("Error: Could not locate the script code on the page. The structure may have changed.")
        return None

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

    finally:
        print("Closing the WebDriver...")
        driver.quit()

# Test the function
if __name__ == "__main__":
    url = "https://codeshare.frida.re/@segura2010/android-certificate-pinning-bypass/"
    print("Starting scraping process...")
    script_code = scrape_codeshare_selenium(url)
    
    if script_code:
        print("\n--- Script Code ---\n")
        print(script_code)
    else:
        print("No script code retrieved.")
