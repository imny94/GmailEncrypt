# The best way to complain is to make things

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import re
import time

class CredentialsGetter():
	'''
	This Class contains the webscrapper required to fetch the relevant authentication details to 
	authenticate with Google. The main purpose of this class is to create the relevant credentials 
	on Google for the project, and then to download the required JSON file.

	To run the class in the right order, execute start() method.

	This class takes in 2 arguments on initialisation, username and password

	Note: 
		Development of this webscrapper is done in selenium, and would require selenium to be installed.
		Install selenium from the command line using command : "pip install selenium" on the command line with pip installed. 
		Development of this class is based on firefox, and would require firefox and geckodriver installed.
		Install the latest version of geckodriver from this link: https://github.com/mozilla/geckodriver/releases
		and ensure geckodriver is in a location accessible by PATH Variable.

	ARGS:
		username: Users gmail email address to login into google
		password: Users gmail email password

	'''

	def __init__(self,username,password):
		'''
		Initialises the class 

		ARGS:
			username: Users gmail email address to login into google
			password: Users gmail email password
		'''
		self.username = username
		self.password = password
		self.driver = driver = webdriver.Firefox()

	'''
	Entry Point to start Web Scrapper
	'''

	def start(self):
		'''
		Starts the webscrapper service. It will open up a browser in firefox and carry out the relevant steps
		to create and obtain the relevant credential information.

		Based on current version, User input is required on the last step, where user has to select the option
		"Others" in the list of radio button given, and enter in a desired credential name in the text box that follows.

		Click Create and press ok to close the resulting text box that follows. 

		Find the Corresponding JSON File on the page shown and download it to the same location as this script.

		!!! Make sure to rename the file to "client_id.json" !!!

		'''
		driver = self.driver
		driver.get('https://console.developers.google.com/start/api?id=gmail')
		self.__login()
		self.__createProject()
		self.__createProjectContinue()
		self.__clickCancel()
		self.__selectOAuthConsentScreen()
		self.__saveOAuthInfo()
		self.__clickCreateOAuthCredentials()
		self.__createCredentials()
		# self.downloadJSON()

	'''
	Below are all private classes used to mimic human interaction with the firefox browser to download required credentials
	'''

	def __login(self):
		driver = self.driver
		username_field = driver.find_element_by_id("Email")
		username_field.send_keys(self.username)
		driver.find_element_by_id("next").click()
		try:
			login_page = WebDriverWait(driver,10).until(EC.presence_of_element_located((By.ID,"Passwd")))
			password_field= driver.find_element_by_id("Passwd")
			password_field.send_keys(self.password)
			driver.find_element_by_id("signIn").click()
		except TimeoutException:
			self.__errorMessage()
			self.login()

		print "Login Success!"

	def __createProject(self):
		driver = self.driver
		try:
			go_to_credentials_page = WebDriverWait(driver,50).until(EC.presence_of_element_located((By.ID,"p6n-api-flow-continue")))
			driver.find_element_by_id("p6n-api-flow-continue").click()
		except TimeoutException:
			self.__errorMessage()
			self.createProject()

		print "Choose to create project success!"

	def __createProjectContinue(self):
		driver = self.driver
		try:
			go_to_credentials_page = WebDriverWait(driver,50).until(EC.presence_of_element_located((By.ID,"p6n-api-flow-to-credentials")))
			driver.find_element_by_id("p6n-api-flow-to-credentials").click()
		except TimeoutException:
			self.__errorMessage()
			self.createProjectContinue()

		print "Go to Credentials button pressed!"

	def __clickCancel(self):
		driver = self.driver
		try:
			create_project_page =  WebDriverWait(driver,10).until(EC.presence_of_element_located((By.XPATH,"/html/body/div[2]/div[2]/div[3]/div[1]/div/md-content/div/div[2]/div/div/form/div[2]/div/jfk-button")))
			driver.find_element_by_xpath("/html/body/div[2]/div[2]/div[3]/div[1]/div/md-content/div/div[2]/div/div/form/div[2]/div/jfk-button").click()
		except TimeoutException:
			self.__errorMessage()
			self.clickCancel()
		print "Cancel Button Pressed!"

	def __selectOAuthConsentScreen(self):
		driver = self.driver
		try:
			go_to_credentials_page = WebDriverWait(driver,10).until(EC.presence_of_element_located((By.XPATH,"/html/body/div[2]/div[2]/div[3]/div[1]/div/md-content/div/div[1]/ng-include/div/g-tab-bar/div")))
			print "OAuth tab loaded!"
			currentURL = driver.current_url
			self.credentialsHomePage = currentURL
			newURL = re.sub(r"credentials\?","credentials/consent?",currentURL)
			driver.get(newURL)

		except TimeoutException:
			self.__errorMessage()
			self.selectOAuthConsentScreen()
		print "Selected OAuthConsentScreen"

	def __saveOAuthInfo(self):
		driver = self.driver
		try:
			go_to_credentials_page = WebDriverWait(driver,10).until(EC.presence_of_element_located((By.ID,"p6n-consent-product-name")))
			product_name_field = driver.find_element_by_id("p6n-consent-product-name")
			product_name_field.send_keys("GmailEncrypt")
			time.sleep(1)
			driver.find_element_by_id("api-consent-save").click()
			time.sleep(1)
			driver.find_element_by_id("api-consent-save").click()
		except TimeoutException:
			self.__errorMessage()
			self.saveOAuthInfo()
		print "OAuth Info Saved!"

	def __clickCreateOAuthCredentials(self):
		driver = self.driver
		try:
			create_credentials_page = WebDriverWait(driver,50).until(EC.presence_of_element_located((By.ID,"p6n-history-input")))
			
			currentURL = driver.current_url
			while currentURL!=self.credentialsHomePage:
				currentURL = driver.current_url 

			newURL = re.sub(r"credentials\?","credentials/oauthclient?",currentURL)
			driver.get(newURL)

		except TimeoutException:
			self.__errorMessage()
			self.clickCreateOAuthCredentials()
		print "Clicked created OAuth Credentials!"

	def __createCredentials(self):
		driver = self.driver
		try:
			WebDriverWait(driver,10).until(EC.presence_of_element_located((By.XPATH,"/html/body/div[2]/div[2]/div[3]/div[1]/div/md-content/div/div[2]/div/form/fieldset/div/div/label[6]")))
			# There is a bug with the XPATH, CSS Selectors etc. cannot seem to select correct radio button. 

			# driver.find_element_by_xpath("/html/body/div[2]/div[2]/div[3]/div[1]/div/md-content/div/div[2]/div/form/fieldset/div/div/label[1]").click()
			def enterInput():
				try:
					WebDriverWait(driver,10).until(EC.presence_of_element_located((By.XPATH,"/html/body/div[2]/div[2]/div[3]/div[1]/div/md-content/div/div[2]/div/form/oauth-client-editor/ng-form/div/label/div[1]/input")))
					driver.find_element_by_xpath("/html/body/div[2]/div[2]/div[3]/div[1]/div/md-content/div/div[2]/div/form/oauth-client-editor/ng-form/div/label/div[1]/input").send_keys("GmailEncrypt")
				except TimeoutException:
					self.__errorMessage()
					enterInput()
				print "Entered Product Name!"
			# enterInput()
			# driver.find_element_by_xpath("/html/body/div[2]/div[2]/div[3]/div[1]/div/md-content/div/div[2]/div/form/div/div/button").click()
		except TimeoutException:
			self.__errorMessage()
			self.createCredentials()
		print "Created Credentials!"

	def __downloadJSON(self):
		driver = self.driver
		try:
			WebDriverWait(driver,50).until(EC.presence_of_element_located((By.ID,"dialogContent_3")))
			driver.find_element_by_name("cancel").click() # Press ok to close dialog
			driver.find_element_by_xpath("/html/body/div[2]/div[2]/div[3]/div[1]/div/md-content/div/div[2]/div/section/table/tbody/tr/td[6]/a/div").click() # Press download
		except TimeoutException:
			self.__errorMessage()
			self.downloadJSON()
		print "Downloaded JSON!"


	def __errorMessage(self):
		print "Error, Trying again...\nIf Error Persists, or web browser stops interacting, refer to ReadMe for more instructions."