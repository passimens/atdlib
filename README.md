# atdlib

atdlib.py - Helper module for communicating with McAfee Advanced Threat Defense via REST API

The module exposes a part of McAfee ATD REST API through a single object atdsession.
It allows one to:
 - upload a file to the ATD box for analysis and get corresponding job id,
 - check job and task status for previously submitted samples,
 - get the analysis report for a given task in a given format.

Proxy along with optional username/password can be specified through HTTP_PROXY/HTTPS_PROXY environment variable inherently to requests library (http://docs.python-requests.org/).
Log level and format is controlled via atdlib logger, logging module (https://docs.python.org/2/library/logging.html).

The module was written in Python 2.7 according to the McAfee ATD API reference guide: https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/26000/PD26048/en_US/ATD_3_4_8_API_Reference_Guide_revA_en_us.pdf.
Tested with ATD v.3.4.8.x (API v.1.5.0).

utests.py - unit test set for the atdlib module. Requires proper initialization of test data (comments inside).

CLASSES
    
    class ATDAuthError(ATDClientError)
     |  Exception is raised when ATD box or a transparent proxy responds with HTTP 401 code

    class ATDClientError(ATDError)
     |  Exception is raised when ATD box or an intermediate proxy responds with HTTP 4xx status code

    class ATDError(exceptions.Exception)
     |  Base exception class for all ATD related errors

    class ATDFailureError(ATDError)
     |  Exception is raised when ATD box returns failure result to last request

    class ATDServerError(ATDError)
     |  Exception is raised when ATD box or an intermediate proxy responds with 5xx status code

    class ATDStateError(ATDError)
     |  Exception is raised when the session is not in a valid state for the method


	class atdsession
     |  Class maintaining ATD connectivity through API.
     |  
     |  Methods defined here:
     |  
     |  __init__(self, ssl=True, uag='Python ATD Client')
     |      Instantiate a new session object with options.
     |      Set ssl to False if you like to connect using plain HTTP (ATD must not redirect to HTTPS),
     |      Set uag to a desired User-Agent header value.
     |  
     |  bulkstatus(self, tasks=(), jobs=())
     |      Gets status for a bulk of task ids or job ids.
     |      tasks - a list of taskIds to check brief analysis status.
     |      jobs - a list of jobIds to check brief analysis status.
     |      Returns list [<list of dicts>].
     |  
     |  close(self)
     |      Closes an open session.
     |      Returns True if successful, False otherwise.
     |  
     |  fileup(self, filename, srcip='', reanalyze=False)
     |      Uploads file to ATD for analysis.
     |      filename - absolute or relative path to the file being analyzed,
     |      srcip - string representing source IP address for reporting purposes.
     |      reanalyze - boolean, whether to forcibly reanalyze previously submitted sample.
     |      Returns analysis job id.
     |  
     |  jobstatus(self, jobid)
     |      Gets sample status based on jobid.
     |      jobid - jobId for a previous submission to check status.
     |      Returns dict {"status": -1..5, "severity": -6..5}.
     |  
     |  jobtasks(self, jobid)
     |      Gets taskid list for a given jobid.
     |      jobid - jobId for a previous submission to get task id list.
     |      Returns list ['<taskid1>', '<taskid2>', ...].
     |  
     |  md5status(self, md5h)
     |      Gets sample status based on md5 hash.
     |      md5h - MD5 hash sum to check previous analysis status.
     |      Returns dict {"status": -1..5, "severity": -6..5, "jobId": <jobId>}.
     |  
     |  open(self, host, user, pswd)
     |      Opens a new session to an ATD box.
     |      Call open() before any further communication. To close session use close()
     |      host - ATD hostname, IP address with optional port: "10.0.0.1[:443]",
     |      user - ATD username to use for authentication,
     |      pswd - respective password to use for authentication.
     |      Returns True if successful, False not expected.
     |  
     |  reset(self)
     |      Resets a session to initial invalid state.
     |      Useful to reopen a new session when close() method fails.
     |      Returns None
     |  
     |  taskreport(self, taskid, type='pdf')
     |      Gets report content for sample based on taskid.
     |      taskid - taskId to get the report for.
     |      Returns report content with content type specified.
     |  
     |  taskstatus(self, taskid)
     |      Gets task status with generic sample info.
     |      taskid - taskId to check brief analysis status.
     |      Returns tasks istate (1|2 - completed, 3 - being analyzed, 4 - waiting, -1 - failed).
     |  
