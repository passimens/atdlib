import atdlib
from atdlib import *
import logging
import unittest

# ------------------------------------
global host, user, pswd, file, srcip, md5s, jobid, taskid, jobs, sjobs, tasks, stasks, ssl

# ----- Please verify the following test data -----
# ---- before running to get meaningful results ---
ssl = True									# Use ssl connection. Can be True or False
host = '169.254.254.100'					# IP-address or hostname of your ATD box
user = 'atduser'							# Your ATD user with REST-API access
pswd = 'atdpassword'						# The respective password
file = 'sample.exe'							# Sample file for upload, located in the working dir
srcip = '10.10.10.10'						# Any valid IP address for enriching sample context
md5s = '10e4a1d2132ccb5c6759f038cdb6f3c9'	# MD5 hash sum of the sample file
jobid = 39									# The id of an existing job on the ATD box
taskid = 62									# The id of an existing task on the ATD box
jobs = (39, 40, 41)							# The tuple of existing jobs' ids on the ATD box
sjobs = ('39', '40', '41')					# Same as above (string values)
tasks = (62, 63, 64)						# The tuple of existing tasks' ids on the ATD box
stasks = ('62', '63', '64')					# Same as above (string values)
# --------------------------------------------------


# ---- Constructor Test Case ---------
class TestATDConstructor(unittest.TestCase):

	def setUp(self):
		self.atd = None
		
	def tearDown(self):
		del self.atd

	def test_atdsession_sslstr(self):
		with self.assertRaises(TypeError):
			self.atd = atdsession(ssl='abc')
			
	def test_atdsession_uagnum(self):
		with self.assertRaises(TypeError):
			self.atd = atdsession(uag=123)
# ------------------------------------

# ---- Open Method Test Case ---------
class TestATDOpenMethod(unittest.TestCase):

	def setUp(self):
		self.atd = atdsession(ssl=ssl)
		
	def tearDown(self):
		self.atd.reset()
		del self.atd

	def test_open(self):
		self.assertEqual(self.atd.open(host, user, pswd), True)
		
	def test_open_dup(self):
		self.atd.open(host, user, pswd)
		with self.assertRaises(ATDStateError):
			self.atd.open(host, user, pswd)

	def test_open_numhname(self):
		with self.assertRaises(TypeError):
			self.atd.open(123, user, pswd)
			
	def test_open_numuname(self):
		with self.assertRaises(TypeError):
			self.atd.open(host, 123, pswd)
			
	def test_open_emptyuname(self):
		with self.assertRaises(ATDAuthError):
			self.atd.open(host, '', pswd)
			
	def test_open_nonexistuname(self):
		with self.assertRaises(ATDClientError):
			self.atd.open(host, 'definitelynotauser', pswd)

	def test_open_numpasswd(self):
		with self.assertRaises(TypeError):
			self.atd.open(host, user, 123)

	def test_open_emptypasswd(self):
		with self.assertRaises(ATDAuthError):
			self.atd.open(host, user, '')
			
	def test_open_wrongpasswd(self):
		with self.assertRaises(ATDAuthError):
			self.atd.open(host, user, 'McAfee123')
# ------------------------------------

# ---- Close Method Test Case ---------
class TestATDCloseMethod(unittest.TestCase):

	def setUp(self):
		self.atd = atdsession(ssl=ssl)
		self.atd.open(host, user, pswd)
		
	def tearDown(self):
		self.atd.reset()
		del self.atd
		
	def test_close(self):
		self.assertEqual(self.atd.close(), True)
		
	def test_close_dup(self):
		self.atd.close()
		with self.assertRaises(ATDStateError):
			self.atd.close()
# ------------------------------------
			
# ---- Fileup Method Test Case ---------
class TestATDFileupMethod(unittest.TestCase):

	def setUp(self):
		self.atd = atdsession(ssl=ssl)
		self.atd.open(host, user, pswd)
		
	def tearDown(self):
		self.atd.close()
		del self.atd

	def test_fileup_ip_nore(self):
		self.assertGreater(self.atd.fileup(file, srcip, False), 0)
		
	def test_fileup_noip_nore(self):
		self.assertGreater(self.atd.fileup(file, '', False), 0)
		
	def test_fileup_ip_re(self):
		self.assertGreater(self.atd.fileup(file, srcip, True), 0)
		
	def test_fileup_noip_re(self):
		self.assertGreater(self.atd.fileup(file, '', True), 0)

	def test_fileup_num_fname(self):
		with self.assertRaises(TypeError):
			self.atd.fileup(123, srcip, True)
		
	def test_fileup_empty_fname(self):
		with self.assertRaises(IOError):
			self.atd.fileup('', srcip, True)
			
	def test_fileup_num_srcip(self):
		with self.assertRaises(TypeError):
			self.atd.fileup(file, 123, True)
			
	def test_fileup_str_reanalyze(self):
		with self.assertRaises(TypeError):
			self.atd.fileup(file, srcip, '')
# ------------------------------------

# ---- _MD5Log Method Test Case ---------
class TestATD_MD5LogMethod(unittest.TestCase):

	def setUp(self):
		self.atd = atdsession(ssl=ssl)
		self.atd.open(host, user, pswd)
		self.ret = None
		
	def tearDown(self):
		self.atd.close()
		del self.atd
		del self.ret

	def test__md5log(self):
		self.ret = self.atd._md5log(md5s)
		self.assertIsInstance(self.ret, dict)
		self.assertIn('success', self.ret)
		self.assertEqual(self.ret['success'], True)
		#print self.ret
		
	def test__md5log_nonexist(self):
		self.ret = self.atd._md5log('00000000000000000000000000000000')
		self.assertIsInstance(self.ret, dict)
		self.assertIn('success', self.ret)
		self.assertEqual(self.ret['success'], True)
		#print self.ret

	def test__md5log_empty_md5(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd._md5log('')
			
	def test__md5log_num_md5(self):
		with self.assertRaises(TypeError):
			self.ret = self.atd._md5log(123)
# ------------------------------------

# ---- MD5Status Method Test Case ---------
class TestATDMD5StatusMethod(unittest.TestCase):

	def setUp(self):
		self.atd = atdsession(ssl=ssl)
		self.atd.open(host, user, pswd)
		self.ret = None
		
	def tearDown(self):
		self.atd.close()
		del self.atd
		del self.ret

	def test_md5status(self):
		self.ret = self.atd.md5status(md5s)
		self.assertIsInstance(self.ret, dict)
		self.assertIn('status', self.ret)
		self.assertIn('severity', self.ret)
		#print self.ret
		
	def test_md5status_nonexist(self):
		self.ret = self.atd.md5status('00000000000000000000000000000000')
		self.assertIsInstance(self.ret, dict)
		self.assertEqual(self.ret['status'], 0)
		self.assertEqual(self.ret['severity'], -6)
		#print self.ret

	def test_md5status_empty_md5(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.md5status('')
			
	def test_md5status_num_md5(self):
		with self.assertRaises(TypeError):
			self.ret = self.atd.md5status(123)
# ------------------------------------

# ---- JobStatus Method Test Case ---------
class TestATDJobStatusMethod(unittest.TestCase):

	def setUp(self):
		self.atd = atdsession(ssl=ssl)
		self.atd.open(host, user, pswd)
		self.ret = None
		
	def tearDown(self):
		self.atd.close()
		del self.atd
		del self.ret

	def test_jobstatus_int(self):
		self.ret = self.atd.jobstatus(jobid)
		self.assertIsInstance(self.ret, dict)
		self.assertIn('status', self.ret)
		self.assertIn('severity', self.ret)
		#print self.ret

	def test_jobstatus_intstr(self):
		self.ret = self.atd.jobstatus(str(jobid))
		self.assertIsInstance(self.ret, dict)
		self.assertIn('status', self.ret)
		self.assertIn('severity', self.ret)
		#print self.ret
		
	def test_jobstatus_nonexist(self):
		# current API implementation returns ATDError
		with self.assertRaises((ATDClientError, ATDError)):
			self.ret = self.atd.jobstatus(65535)
		
	def test_jobstatus_str(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.jobstatus("justastring")
			
	def test_jobstatus_emptystr(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.jobstatus("")
		
# ------------------------------------

# ---- TaskStatus Method Test Case ---------
class TestATDTaskStatusMethod(unittest.TestCase):

	def setUp(self):
		self.atd = atdsession(ssl=ssl)
		self.atd.open(host, user, pswd)
		self.ret = None
		
	def tearDown(self):
		self.atd.close()
		del self.atd
		del self.ret

	def test_taskstatus_int(self):
		self.ret = self.atd.taskstatus(taskid)
		self.assertIsInstance(self.ret, int)
		self.assertIn(self.ret, [1,2,3,4,-1])
		#print self.ret

	def test_taskstatus_intstr(self):
		self.ret = self.atd.taskstatus(str(taskid))
		self.assertIsInstance(self.ret, int)
		self.assertIn(self.ret, [1,2,3,4,-1])
		#print self.ret
		
	def test_taskstatus_nonexist(self):
		# current API implementation returns ATDClientError
		with self.assertRaises((ATDClientError, ATDError)):
			self.ret = self.atd.taskstatus(65535)
		
	def test_taskstatus_str(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.taskstatus("justastring")
			
	def test_taskstatus_emptystr(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.taskstatus("")
# ------------------------------------

# ---- JobTasks Method Test Case ---------
class TestATDJobTasksMethod(unittest.TestCase):

	def setUp(self):
		self.atd = atdsession(ssl=ssl)
		self.atd.open(host, user, pswd)
		self.ret = None
		
	def tearDown(self):
		self.atd.close()
		del self.atd
		del self.ret

	def test_jobtasks_int(self):
		self.ret = self.atd.jobtasks(jobid)
		self.assertIsInstance(self.ret, list)
		self.assertGreater(len(self.ret), 0)
		#print self.ret

	def test_jobtasks_intstr(self):
		self.ret = self.atd.jobtasks(str(jobid))
		self.assertIsInstance(self.ret, list)
		self.assertGreater(len(self.ret), 0)
		#print self.ret
		
	def test_jobtasks_nonexist(self):
		# current API implementation returns empty list
		self.ret = self.atd.jobtasks(65535)
		self.assertIsInstance(self.ret, list)
		self.assertEqual(len(self.ret), 0)
		#print self.ret
		
	def test_jobtasks_str(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.jobtasks("justastring")
			
	def test_jobtasks_emptystr(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.jobtasks("")
		
# ------------------------------------

# ---- BulkStatus Method Test Case ---------
class TestATDBulkStatusMethod(unittest.TestCase):

	def setUp(self):
		self.atd = atdsession(ssl=ssl)
		self.atd.open(host, user, pswd)
		
	def tearDown(self):
		self.atd.close()
		del self.atd

	def test_bulkstatus_tasks(self):
		self.ret = self.atd.bulkstatus(tasks=tasks)
		self.assertIsInstance(self.ret, list)
		self.assertGreater(len(self.ret), 0)
		#print self.ret
		
	def test_bulkstatus_stasks(self):
		self.ret = self.atd.bulkstatus(tasks=stasks)
		self.assertIsInstance(self.ret, list)
		self.assertGreater(len(self.ret), 0)
		#print self.ret
		
	def test_bulkstatus_jobs(self):
		self.ret = self.atd.bulkstatus(jobs=jobs)
		self.assertIsInstance(self.ret, list)
		self.assertGreater(len(self.ret), 0)
		#print self.ret
		
	def test_bulkstatus_sjobs(self):
		self.ret = self.atd.bulkstatus(jobs=sjobs)
		self.assertIsInstance(self.ret, list)
		self.assertGreater(len(self.ret), 0)
		#print self.ret
		
	def test_bulkstatus_tasksjobs(self):
		self.ret = self.atd.bulkstatus(tasks=tasks, jobs=jobs)
		self.assertIsInstance(self.ret, list)
		self.assertGreater(len(self.ret), 0)
		#print self.ret
		
	def test_bulkstatus_nonexisttasks(self):
		#current API returns the list with {taskid=<id>, status=-1, severity=-1} items
		self.ret = self.atd.bulkstatus(tasks=[65535,65534])
		self.assertIsInstance(self.ret, list)
		self.assertEqual(len(self.ret), 2)
		#print self.ret
		
	def test_bulkstatus_nonexistjobs(self):
		#current API returns the list with {jobid=<id>, status=-1, severity=-1} items
		self.ret = self.atd.bulkstatus(jobs=[65535,65534])
		self.assertIsInstance(self.ret, list)
		self.assertEqual(len(self.ret), 2)
		#print self.ret
	
	def test_bulkstatus_notasksnojobs(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.bulkstatus()
		
	def test_bulkstatus_num_tasks(self):
		with self.assertRaises(TypeError):
			self.ret = self.atd.bulkstatus(tasks=123)
			
	def test_bulkstatus_num_jobs(self):
		with self.assertRaises(TypeError):
			self.ret = self.atd.bulkstatus(jobs=123)
		
	def test_bulkstatus_str_tasks(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.bulkstatus(tasks="thisisjustastring")
			
	def test_bulkstatus_str_jobs(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.bulkstatus(jobs="thisisjustastring")

# ------------------------------------

# ---- TaskReport Method Test Case ---------
class TestATDTaskReportMethod(unittest.TestCase):

	def setUp(self):
		self.atd = atdsession(ssl=ssl)
		self.atd.open(host, user, pswd)
		self.ret = None
		
	def tearDown(self):
		self.atd.close()
		del self.atd
		del self.ret

	def test_taskreport_int(self):
		self.ret = self.atd.taskreport(taskid)
		self.assertGreater(len(self.ret), 0)

	def test_taskreport_intstr(self):
		self.ret = self.atd.taskreport(str(taskid))
		self.assertGreater(len(self.ret), 0)
		
	def test_taskreport_list(self):
		with self.assertRaises(TypeError):
			self.ret = self.atd.taskreport(list(taskid))
			
	def test_taskreport_nonexist(self):
		# current API implementation returns ATDClientError
		with self.assertRaises(ATDClientError):
			self.ret = self.atd.taskreport(65535)

	def test_taskreport_invalidreptype(self):
		with self.assertRaises(ValueError):
			self.ret = self.atd.taskreport(taskid=taskid, type='nosuchtype')
# ------------------------------------

# ----------- Main Unit Test -------------
if __name__ == '__main__':

	logFormat = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(message)s')
	logHandler = logging.FileHandler('atdlib14.log')
	logHandler.setFormatter(logFormat)
	mylog = logging.getLogger('atdlib')
	mylog.addHandler(logHandler)
	mylog.setLevel(logging.INFO)

	t = {}
	t['suiteCreate'] = unittest.TestLoader().loadTestsFromTestCase(TestATDConstructor)
	t['suiteOpen'] = unittest.TestLoader().loadTestsFromTestCase(TestATDOpenMethod)
	t['suiteClose'] = unittest.TestLoader().loadTestsFromTestCase(TestATDCloseMethod)
	t['suiteFileup'] = unittest.TestLoader().loadTestsFromTestCase(TestATDFileupMethod)
	t['suiteMD5Status'] = unittest.TestLoader().loadTestsFromTestCase(TestATDMD5StatusMethod)
	t['suite_MD5Log'] = unittest.TestLoader().loadTestsFromTestCase(TestATD_MD5LogMethod)
	t['suiteJobStatus'] = unittest.TestLoader().loadTestsFromTestCase(TestATDJobStatusMethod)
	t['suiteTaskStatus'] = unittest.TestLoader().loadTestsFromTestCase(TestATDTaskStatusMethod)
	t['suiteJobTasks'] = unittest.TestLoader().loadTestsFromTestCase(TestATDJobTasksMethod)
	t['suiteBulkStatus'] = unittest.TestLoader().loadTestsFromTestCase(TestATDBulkStatusMethod)
	t['suiteTaskReport'] = unittest.TestLoader().loadTestsFromTestCase(TestATDTaskReportMethod)
	
	alltests = unittest.TestSuite(t.values())
	#alltests = unittest.TestSuite(t['suiteClose'])
	
	unittest.TextTestRunner(verbosity=5).run(alltests)