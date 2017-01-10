'''
ATDLib v.1.4. (c) 2015 Valeriy V. Filin (valerii.filin@gmail.com).
Exposes a part of McAfee ATD REST API: open session, upload a file, get job/task status, get task report, close session.
Proxy along with optional username/password can be specified through HTTP_PROXY/HTTPS_PROXY environment variable inherently to requests library.
Log level and format is controlled via logging module, atdlib logger.
'''

import json
import requests
from requests import Request, Session
import base64
import urllib
import logging
import re

global atdlog

class ATDError(Exception):
	'''Base exception class for all ATD related errors'''
	'''Exception is explicitly raised when an unknown ATD error'''

class ATDStateError(ATDError):
	'''Exception is raised when the session is not in a valid state for the method'''
	pass

class ATDClientError(ATDError):
	'''Exception is raised when ATD box or an intermediate proxy responds with HTTP 4xx status code'''
	pass

class ATDAuthError(ATDClientError):
	'''Exception is raised when ATD box or a transparent proxy responds with HTTP 401 code'''
	pass

class ATDServerError(ATDError):
	'''Exception is raised when ATD box or an intermediate proxy responds with 5xx status code'''
	pass

class ATDFailureError(ATDError):
	'''Exception is raised when ATD box returns failure result to last request'''
	pass


class atdsession:
	'''Class maintaining ATD connectivity through API.'''

	# ------- Public static class attributes -------

	apiver = '1.5.0' # API version implemented/required
	debug = False

	def __init__(self, ssl=True, uag='Python ATD Client'):
		'''Instantiate a new session object with options.
		Set ssl to False if you like to connect using plain HTTP (ATD must not redirect to HTTPS),
		Set uag to a desired User-Agent header value.'''

		if not isinstance(ssl, bool):raise TypeError(__name__ + u': ssl parameter must be True or False')
		if not isinstance(uag, str): raise TypeError(__name__ + u': uag parameter must be a string')

		# ------- Private class instance attributes -------
		self._atdhost = ''	# Hostname of an ATD box to connect to
		self._userid = ''	# User id returned on successful authentication
		self._sessid = ''	# Session id returned on successful authentication
		self._auth = ''		# Encoded pair "_userid : _sessid"
		self._valid = False	# Is session valid (connected to ATD)
		self._usessl = ssl	# Use SSL encryption for ATD communication
		self._userag = uag	# User-Agent string to use in HTTP headers

		self._headers = {'Accept': 'application/vnd.ve.v1.0+json',
						 'VE-API-Version': atdsession.apiver,
						 'user-agent': self._userag}


	# ===== Private class methods =====

	# --- atdsession._reqsend() method ---
	def _reqsend(self, prep, host=''):
		'''Sends prepared request.
		Used by all other methods.
		Returns raw response.
		'''

		atdlog.info(u'------- Sending {0} request to host {1} -------'.format(prep.method, host))

		s = Session()

		resp = s.send(prep, verify=False)
		atdlog.debug(u'server response: {0}'.format(resp.text))

		if resp.status_code == 401:
			atdlog.error(u'Could not authenticate to ATD box {0}.'.format(host))
			raise ATDAuthError(__name__ + u': Could not authenticate to ATD box {0}.'.format(host))

		if resp.status_code != 200 :
			desc = __name__ + u': ATD box {0} returned HTTP error {1}.'.format(self._atdhost, resp.status_code)
			atdlog.error(desc)
			if 400 <= resp.status_code < 500:	raise ATDClientError(desc)
			elif 500 <= resp.status_code < 600:	raise ATDServerError(desc)
			else:								raise ATDError(desc)

		return resp

	# --- atdsession._parse() method ---
	def _parse(self, src, parser):
		'''Parses source text as json entity.
		Returns result of parser(src).
		Raises ATDError if resp is not json, or json does not contain the values expected by parser.
		'''
		atdlog.info(u'------- Parsing {0}-byte server response -------'.format(len(src)))
		atdlog.debug(u'text to parse = "{0}"'.format(src))

		try:
			res = json.loads(src)
		except ValueError as e:
			atdlog.error(u'ATD box {0} did not return a valid json output.'.format(self._atdhost))
			raise ATDError(__name__ + u': ATD box {0} did not return a valid json output.'.format(self._atdhost))

		atdlog.debug(u'json data = "{0}"'.format(res))

		try:
			success = res['success']
		except KeyError as e:
			atdlog.error(u'ATD box {0} returned unexpected data.'.format(self._atdhost))
			raise ATDError(__name__ + u': ATD box {0} returned unexpected data.'.format(self._atdhost))

		if success == False:
			message = res['message'] if 'message' in res else ''
			atdlog.error(u'ATD box {0} returned failure message: {1}.'.format(self._atdhost, message))
			raise ATDFailureError(__name__ + u': ATD box {0} returned failure message: {1}.'.format(self._atdhost, message))

		try:
			return parser(res)
		except:
			atdlog.error(u'ATD box {0} returned unexpected data.'.format(self._atdhost))
			raise ATDError(__name__ + u': ATD box {0} returned unexpected data.'.format(self._atdhost))


	# ===== Public class methods =====

	# --- atdsession.open() method ---
	def open(self, host, user, pswd):
		'''Opens a new session to an ATD box.
		Call open() before any further communication. To close session use close()
		host - ATD hostname, IP address with optional port: "10.0.0.1[:443]",
		user - ATD username to use for authentication,
		pswd - respective password to use for authentication.
		Returns True if successful, False not expected.
		'''

		atdlog.info(u'------- Opening new session to server {0} with user {1} -------'.format(host, user))

		if self._valid:
			atdlog.error(u'Session already open to host {0}. Please run close() or reset() method first.'.format(self._atdhost))
			raise ATDStateError(
				__name__ + u': Session already open to host {0}. Please run close() or reset() method first.'.format(self._atdhost)
			)

		if not isinstance(host, str): raise TypeError(__name__ + u': host parameter must be a string')
		if not isinstance(user, str): raise TypeError(__name__ + u': user parameter must be a string')
		if not isinstance(pswd, str): raise TypeError(__name__ + u': pswd parameter must be a string')

		url = 'http' + ('s' if self._usessl else '') + '://' + host + '/php/session.php'
		auth = base64.b64encode(user + ':' + pswd)

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': auth, 'Content-Type' : 'application/json'})

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))

		req = Request('GET', url, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, host)

		self._userid, self._sessid = self._parse(resp.text, lambda x: (x['results']['userId'], x['results']['session']))

		self._atdhost = host
		self._auth = base64.b64encode(self._sessid + ':' + self._userid)
		self._valid = True

		return True


	# --- atdsession.close() method ---
	def close(self):
		'''Closes an open session.
		Returns True if successful, False otherwise.'''

		atdlog.info(u'------- Closing current session to server {0} -------'.format(self._atdhost))
		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/session.php'

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth, 'Content-Type' : 'application/json'})

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))

		req = Request('DELETE', url, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		null = self._parse(resp.text, lambda x: x['success'])

		self._valid = False
		return True


	# --- atdsession.reset() method ---
	def reset(self):
		'''Resets a session to initial invalid state.
		Useful to reopen a new session when close() method fails.
		Returns None
		'''
		atdlog.info(u'------- Resetting session -------')
		self._valid = False

	# ----------------------------------------------------------------------------------
	# --- atdsession.fileup() method ---
	def fileup(self, filename, srcip='', reanalyze=False):
		'''Uploads file to ATD for analysis.
		filename - absolute or relative path to the file being analyzed,
		srcip - string representing source IP address for reporting purposes.
		reanalyze - boolean, whether to forcibly reanalyze previously submitted sample.
		Returns analysis job id.
		'''

		atdlog.info(u'------- Sending file {0} to server {1} -------'.format(repr(filename), self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		if not isinstance(filename, basestring): raise TypeError(__name__ + u': filename parameter must be an ascii or unicode string')
		if not isinstance(srcip, str): raise TypeError(__name__ + u': srcip parameter must be a string')
		if not isinstance(reanalyze, bool): raise TypeError(__name__ + u': reanalyze parameter must be a bool')

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/fileupload.php'

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth})

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))
		atdlog.debug(u'filename = "{0}"'.format(filename))

		data = json.dumps({'data': {'srcIp': srcip, 'analyzeAgain': '1' if reanalyze else '0'}})
		postdata = {'data': data}

		file_up = {'amas_filename': open(filename, 'rb')}

		s = Session()
		req = Request('POST', url, data=postdata, files=file_up, headers=headers)

		prep = req.prepare()

		'''
		newbody = ''
		for line in prep.body.splitlines(True) :
			if "Content-Disposition: form-data; name=\"amas_filename\"; filename*=utf-8''" in line :
				line = line.replace("filename*=utf-8''", "filename=\"").replace("\r\n","\"\r\n")
				line = urllib.unquote(line)
				#line = requests.packages.urllib3.unquote(line)

			newbody += line
		'''
		li = str.find(prep.body, "Content-Disposition: form-data; name=\"amas_filename\"; filename*=utf-8''")
		if li >= 0:
			ri = str.find(prep.body, "\r\n", li)
			if ri >= 0:
				newbody = prep.body[:li] + 'Content-Disposition: form-data; name="amas_filename"; filename="' +	urllib.unquote(prep.body[li+71:ri]) + '"' + prep.body[ri:]
				prep.body = newbody
				prep.headers['Content-Length'] = str(len(newbody))

		resp = self._reqsend(prep, self._atdhost)

		return self._parse(resp.text, lambda x: x['subId'])


	# --- atdsession.md5log() method ---
	def _md5log(self, md5h):
		'''Gets sample status history based on md5 hash.
		md5h - MD5 hash sum to check previous analysis status.
		Returns a raw status output for md5 request.
		'''

		atdlog.info(u'------- Retrieving analysis log for MD5={0} from server {1} -------'.format(md5h, self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		if not isinstance(md5h, str): raise TypeError(__name__ + u': md5h parameter must be a string')

		if not re.search(r'([a-fA-F\d]{32})', md5h):
			atdlog.error(u'"{0}" is not a valid MD5 hash.'.format(md5h))
			raise ValueError(__name__ + u': md5h parameter must be a valid hash')

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth, 'Content-Type' : 'application/json'})

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/samplestatus.php?userid=' + self._userid + '&md5=' + md5h

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))

		req = Request('GET', url, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		return self._parse(resp.text, lambda x: x)


	# --- atdsession.md5status() method ---
	def md5status(self, md5h):
		'''Gets sample status based on md5 hash.
		md5h - MD5 hash sum to check previous analysis status.
		Returns dict {"status": -1..5, "severity": -6..5, "jobId": <jobId>}.
		'''

		atdlog.info(u'------- Retrieving status for MD5={0} from server {1} -------'.format(md5h, self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		if not isinstance(md5h, str): raise TypeError(__name__ + u': md5h parameter must be a string')

		if not re.search(r'([a-fA-F\d]{32})', md5h):
			atdlog.error(u'"{0}" is not a valid MD5 hash.'.format(md5h))
			raise ValueError(__name__ + u': md5h parameter must be a valid hash')

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth, 'Content-Type' : 'application/json'})

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/samplestatus.php?userid=' + self._userid + '&md5=' + md5h

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))

		req = Request('GET', url, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		count = int( self._parse(resp.text, lambda x: x['totalCount']) )

		if count > 0:
			log = self._parse(resp.text, lambda x: x['results'])
			# Sort previous submissions based on lastChange time
			try:
				rr = sorted(log, key=lambda x: x['lastChange'], reverse=True)
				# Return latest result
				return {'status': rr[0]['status'], 'jobid': rr[0]['jobid'], 'severity': rr[0]['severity']}
			except (KeyError, IndexError) as e:
				atdlog.error(u'ATD box {0} returned unexpected data.'.format(self._atdhost))
				raise ATDError(__name__ + u': ATD box {0} returned unexpected data.'.format(self._atdhost))

		# Nothing found in completed or running analyses
		else :
			# Nothing found in running on completed analyses
			return {'status': 0, 'severity': -6}


	# --- atdsession.jobstatus() method ---
	def jobstatus(self, jobid):
		'''Gets sample status based on jobid.
		jobid - jobId for a previous submission to check status.
		Returns dict {"status": -1..5, "severity": -6..5}.
		'''

		atdlog.info(u'------- Retrieving status for job id {0} from server {1} -------'.format(jobid, self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		jobid = int(jobid)

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth, 'Content-Type' : 'application/json'})

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/samplestatus.php?jobId=' + str(jobid)

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))

		req = Request('GET', url, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		return self._parse(resp.text, lambda x: x)


	# --- atdsession.taskstatus() method ---
	def taskstatus(self, taskid):
		'''Gets task status with generic sample info.
		taskid - taskId to check brief analysis status.
		Returns tasks istate (1|2 - completed, 3 - being analyzed, 4 - waiting, -1 - failed).
		'''

		atdlog.info(u'------- Retrieving status for task id {0} from server {1} -------'.format(taskid, self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		taskid = int(taskid)

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth, 'Content-Type' : 'application/json'})

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/samplestatus.php?iTaskId=' + str(taskid)

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))

		req = Request('GET', url, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		return self._parse(resp.text, lambda x: x['results']['istate'])


	# --- atdsession.jobtasks() method ---
	def jobtasks(self, jobid):
		'''Gets taskid list for a given jobid.
		jobid - jobId for a previous submission to get task id list.
		Returns list ['<taskid1>', '<taskid2>', ...].
		'''

		atdlog.info(u'------- Retrieving list of tasks for job id {0} from server {1} -------'.format(jobid, self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		jobid = int(jobid)

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth, 'Content-Type' : 'application/json'})

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/getTaskIdList.php?jobId=' + str(jobid)

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))

		req = Request('GET', url, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		return self._parse(resp.text, lambda x: x['result']['taskIdList'].split(',') if len(x['result']) > 0 else [])


	# --- atdsession.bulkstatus() method ---
	def bulkstatus(self, tasks=(), jobs=()):
		'''Gets status for a bulk of task ids or job ids.
		tasks - a list of taskIds to check brief analysis status.
		jobs - a list of jobIds to check brief analysis status.
		Returns list [<list of dicts>].
		'''

		atdlog.info(u'------- Retrieving bulk status for (tasks {0}, jobs {1}) from server {2} -------'.format(tasks, jobs, self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		if tasks:
			ts = [int(task) for task in tasks]
			postdata = {'data': '{"bulkrequest":{"numRequest":' + str(len(ts)) + ',"taskIDs":' + str(ts) + '}}'}
		elif jobs:
			js = [int(job) for job in jobs]
			postdata = {'data': '{"bulkrequest":{"numRequest":' + str(len(js)) + ',"jobIDs":' + str(js) + '}}'}
		else:
			raise ValueError('Either tasks or jobs list must be given')

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/getBulkStatus.php'

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth})

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))
		atdlog.debug(u'postdata: {}'.format(postdata))

		req = Request('POST', url, data=postdata, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		return self._parse(resp.text, lambda x: x['results']['bulkresponse']['status'])


	# --- atdsession.taskreport() method ---
	def taskreport(self, taskid, type="pdf"):
		'''Gets report content for sample based on taskid.
		taskid - taskId to get the report for.
		Returns report content with content type specified.
		'''

		atdlog.info(u'------- Retrieving task report in {0} for task id {1} from server {2} -------'.format(type, taskid, self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		taskid = int(taskid)

		if type not in ('html', 'txt', 'xml', 'zip', 'json', 'ioc', 'stix', 'pdf', 'sample'):
			raise ValueError(__name__ + u': Report type requested is not supported. Supported types are: html, txt, xml, zip, json, ioc, stix, pdf, sample.')

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth, 'Content-Type' : 'application/json'})

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/showreport.php?iTaskId=' + str(taskid) + '&iType=' + type

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))

		req = Request('GET', url, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		return resp.content


	# --- atdsession.md5report() method ---
	def md5report(self, md5h, type="pdf"):
		'''Gets report content for sample based on a md5 hash.
		md5h - md5 hash to get the report for.
		Returns report content with content type specified.
		'''

		atdlog.info(u'------- Retrieving task report in {0} for MD5={1} from server {2} -------'.format(type, md5h, self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		if not isinstance(md5h, str): raise TypeError(__name__ + u': md5h parameter must be a string')

		if not re.search(r'([a-fA-F\d]{32})', md5h):
			atdlog.error(u'"{0}" is not a valid MD5 hash.'.format(md5h))
			raise ValueError(__name__ + u': md5h parameter must be a valid hash')
			
		if type not in ('html', 'txt', 'xml', 'zip', 'json', 'ioc', 'stix', 'pdf', 'sample'):
			raise ValueError(__name__ + u': Report type requested is not supported. Supported types are: html, txt, xml, zip, json, ioc, stix, pdf, sample.')

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth, 'Content-Type' : 'application/json'})

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/showreport.php?md5=' + str(md5h) + '&iType=' + type

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))

		req = Request('GET', url, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		return resp.content

	# --- atdsession.jobreport() method ---
	def jobreport(self, jobid, type="zip"):
		'''Gets report content for sample based on a job ID.
		jobid - The job ID to get the report for.
		Returns report content with content type specified.
		'''

		atdlog.info(u'------- Retrieving task report in {0} for job id {1} from server {2} -------'.format(type, jobid, self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')


		if type not in ('html', 'zip', 'json', 'sample'):
			raise ValueError(__name__ + u': Report type requested is not supported. Supported types are: html, zip, json, sample.')

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth, 'Content-Type' : 'application/json'})

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/showreport.php?jobId=' + str(jobid) + '&iType=' + type

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))

		req = Request('GET', url, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		return resp.content

	# --- atdsession.listlookup() method ---
	def listlookup(self, md5h):
		'''Checks for a hash in the local white and black lists.
		md5h - The MD5 hash to check.
		Returns black/white list indicator: 'b'|'w'|'0'.
		'''

		atdlog.info(u'------- Retrieving list status for MD5={0} from server {1} -------'.format(md5h, self._atdhost))

		if not self._valid:
			atdlog.error(u'Session is not valid. Please run open() method first.')
			raise ATDStateError(__name__ + u': Session is not valid. Please run open() method first.')

		if not isinstance(md5h, str): raise TypeError(__name__ + u': md5h parameter must be a string')

		if not re.search(r'([a-fA-F\d]{32})', md5h):
			atdlog.error(u'"{0}" is not a valid MD5 hash.'.format(md5h))
			raise ValueError(__name__ + u': md5h parameter must be a valid hash')

		postdata = {'data': '{"md5":' + '"' + md5h + '"' + '}'}

		url = 'http' + ('s' if self._usessl else '') + '://' + self._atdhost + '/php/atdHashLookup.php'

		headers = self._headers.copy()
		headers.update({'VE-SDK-API': self._auth})

		atdlog.debug(u'url = "{0}", headers = "{1}"'.format(url, headers))
		atdlog.debug(u'postdata: {}'.format(postdata))

		req = Request('POST', url, data=postdata, headers=headers)
		prep = req.prepare()
		resp = self._reqsend(prep, self._atdhost)

		return self._parse(resp.text, lambda x: x['results'][md5h.upper()])


# --- Initialize module: ---
# Disable SSL security warning
requests.packages.urllib3.disable_warnings()
# Define logger
atdlog = logging.getLogger(__name__)
