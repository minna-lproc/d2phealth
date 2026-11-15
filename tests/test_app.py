import json, sqlite3, tempfile, unittest, uuid
from pathlib import Path
from app import create_app, password_hash, stamp

class SurveyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.app=create_app({'TESTING':True,'INSTANCE_PATH':cls.tmp.name,'SECRET_KEY':'test-only-secret','DATABASE':str(Path(cls.tmp.name)/'test.sqlite3')})
        cls.admin_id=str(uuid.uuid4())
        with sqlite3.connect(cls.app.config['DATABASE']) as db:
            db.execute("INSERT INTO members(id,username,name,role,password_hash,must_change_password,created_at) VALUES(?,? ,?,'admin',?,0,?)",(cls.admin_id,'admin','Administrator',password_hash('AdministratorPassword123'),stamp()))
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def client(self): return self.app.test_client()
    def get(self,c,path): return c.get(path,base_url='https://survey.example')
    def post(self,c,path,data,method='POST'):
        token=self.get(c,'/api/session').get_json()['csrfToken']
        return c.open(path,method=method,json=data,base_url='https://survey.example',headers={'Origin':'https://survey.example','X-CSRF-Token':token})
    def login(self,c,username,password): return self.post(c,'/api/login',{'username':username,'password':password})
    def sample(self,identifier,owner):
        return {'id':identifier,'ownerId':owner,'code':'CHS-'+identifier,'date':'2026-11-14','enumerator':'spoof','language':'bis','modules':[11], 'consentAt':stamp(),'created':stamp(),'updated':stamp(),'status':'complete','answers':{'s1_q1':'42','s1_q2':0,'s2_q1':4,'s9_q4':'7'},'notes':''}
    def test_full_fieldwork_lifecycle(self):
        admin=self.client();alice=self.client();bob=self.client()
        self.assertEqual(self.get(alice,'/api/records').status_code,401)
        self.assertEqual(self.login(admin,'admin','wrong').status_code,401)
        self.assertEqual(self.login(admin,'admin','AdministratorPassword123').status_code,200)
        for name,client in [('Alice',alice),('Bob',bob)]:
            self.assertEqual(self.post(admin,'/api/members',{'username':name.lower(),'name':name,'temporaryPassword':'TemporaryPassword123'}).status_code,201)
            first=self.login(client,name.lower(),'TemporaryPassword123');self.assertTrue(first.get_json()['user']['mustChangePassword'])
            self.assertEqual(self.get(client,'/api/records').status_code,428)
            self.assertEqual(self.post(client,'/api/password',{'currentPassword':'TemporaryPassword123','newPassword':name+'NewPassword12345'}).status_code,200)
        owner=self.get(alice,'/api/me').get_json()['user']['id'];record=self.sample('interview-1',owner)
        def sync(c,r,v): return self.post(c,'/api/sync',{'records':[{'record':r,'expectedVersion':v}]})
        first=sync(alice,record,0);self.assertEqual(first.status_code,200);self.assertEqual(first.get_json()['results'][0]['version'],1)
        self.assertEqual(sync(alice,record,0).get_json()['results'][0]['version'],1)
        stored=self.get(alice,'/api/records').get_json()['records'];self.assertEqual(len(stored),1);self.assertEqual(stored[0]['record']['enumerator'],'Alice')
        self.assertEqual(self.get(bob,'/api/records').get_json()['records'],[])
        self.assertEqual(self.get(bob,'/api/members').status_code,403);self.assertEqual(self.get(bob,'/api/records?team=1').status_code,403)
        self.assertEqual(sync(bob,record,1).status_code,403)
        other=dict(record,ownerId=self.get(bob,'/api/me').get_json()['user']['id'])
        collision=sync(bob,other,1).get_json()['results'][0];self.assertEqual(collision['status'],'blocked');self.assertNotIn('record',collision)
        changed=dict(record,answers=dict(record['answers'],s1_q1='43'))
        self.assertEqual(sync(alice,changed,1).get_json()['results'][0]['version'],2)
        stale=dict(record,notes='Competing offline edits')
        conflict=sync(alice,stale,1).get_json()['results'][0];self.assertEqual(conflict['status'],'conflict');self.assertEqual(conflict['record']['answers']['s1_q1'],'43')
        self.assertEqual(len(self.get(admin,'/api/records?team=1').get_json()['records']),1)
        self.assertEqual(sync(alice,dict(record,answers={'s2_q1':5}),2).status_code,400)
        self.assertEqual(sync(alice,dict(record,answers={'s9_q4':'11'}),2).status_code,400)
        self.assertEqual(sync(alice,dict(record,date='2026-99-99'),2).status_code,400)
        self.assertEqual(sync(alice,dict(record,answers={'s1_q2':True}),2).status_code,400)
        self.assertEqual(sync(alice,dict(record,answers={'s1_q1':'<script>alert(1)</script>'}),2).status_code,400)
        members=self.get(admin,'/api/members').get_json()['members'];alice_id=next(m['id'] for m in members if m['username']=='alice')
        self.assertEqual(self.post(admin,'/api/members/'+alice_id,{'enabled':False},'PATCH').status_code,200)
        self.assertEqual(self.get(alice,'/api/me').status_code,401)
        self.assertEqual(self.login(alice,'alice','AliceNewPassword12345').status_code,401)
        self.assertEqual(self.post(admin,'/api/members/'+alice_id,{'enabled':True},'PATCH').status_code,200)
        self.assertEqual(self.post(admin,'/api/members/'+alice_id,{'temporaryPassword':'ReplacementTemp12345'},'PATCH').status_code,200)
        self.assertEqual(self.login(alice,'alice','AliceNewPassword12345').status_code,401)
        self.assertTrue(self.login(alice,'alice','ReplacementTemp12345').get_json()['user']['mustChangePassword'])
        self.assertEqual(self.post(admin,'/api/members/'+self.admin_id,{'enabled':False},'PATCH').status_code,400)
        with sqlite3.connect(self.app.config['DATABASE']) as db:
            hashed=db.execute("SELECT password_hash FROM members WHERE username='alice'").fetchone()[0];self.assertTrue(hashed.startswith('pbkdf2:sha256:'));self.assertNotIn('Replacement',hashed)
    def test_csrf_cookie_and_assets(self):
        c=self.client();self.get(c,'/api/session')
        self.assertEqual(c.post('/api/login',json={},base_url='https://survey.example').status_code,403)
        token=self.get(c,'/api/session').get_json()['csrfToken']
        self.assertEqual(c.post('/api/login',json={},base_url='https://survey.example',headers={'Origin':'https://evil.example','X-CSRF-Token':token}).status_code,403)
        for path in ['/','/app.js','/cloud.js','/data.js','/sw.js','/manifest.webmanifest','/questionnaire-english.docx','/questionnaire-bisaya.docx']:
            result=self.get(c,path);self.assertEqual(result.status_code,200,path);result.close()
        self.assertEqual(self.get(c,'/instance/survey.sqlite3').status_code,404)
        self.assertEqual(self.get(c,'/app.py').status_code,404)
        r=self.get(c,'/api/session');self.assertEqual(r.headers['Cache-Control'],'no-store')
        self.assertIn('HttpOnly',r.headers.get('Set-Cookie','') or self.get(self.client(),'/api/session').headers['Set-Cookie'])
    def test_login_throttle(self):
        c=self.client()
        for i in range(8): self.assertEqual(self.login(c,'missing-user','bad').status_code,401)
        self.assertEqual(self.login(c,'missing-user','bad').status_code,429)

if __name__=='__main__': unittest.main()
