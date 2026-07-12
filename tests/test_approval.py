import json, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from outrider.approval import *
from outrider.state import transition_state, load_manifest, load_state

class ApprovalTests(unittest.TestCase):
    def make_run(self):
        from outrider.cli import init_run
        import argparse
        tmp=tempfile.TemporaryDirectory(); init_run(argparse.Namespace(target='example.com', output_dir=tmp.name, scope=['example.com','*.example.com'], exclude=['blocked.example.com'], actor='authorized-operator', authorization_reference='EXAMPLE-ROE-001'))
        run=Path(tmp.name)/'example.com'; transition_state(run,'scoped','authorized-operator')
        return tmp, run
    def test_grant_list_revoke_and_decisions(self):
        tmp, run = self.make_run(); self.addCleanup(tmp.cleanup)
        before_m=(run/'manifest.json').read_text(); before_s=(run/'run.jsonl').read_text(); before_e=(run/'evidence.jsonl').read_text()
        now=datetime(2026,1,1,tzinfo=timezone.utc)
        g=grant_approval(run,'target_read_only_request','HTTPS://API.EXAMPLE.COM/path','authorized-operator','Approved bounded read-only review',duration_minutes=60,conditions='No authentication attempts',now=now)
        self.assertEqual(g.sequence,1); self.assertEqual(UUID(g.approval_id).version,4); self.assertEqual(g.candidate,'api.example.com'); self.assertEqual(g.candidate_type,'domain'); self.assertEqual(g.status,'active')
        self.assertEqual((run/'manifest.json').read_text(), before_m); self.assertEqual((run/'run.jsonl').read_text(), before_s); self.assertEqual((run/'evidence.jsonl').read_text(), before_e)
        self.assertEqual(evaluate_action(run,'target_read_only_request','api.example.com',now=now).decision,'allow')
        self.assertEqual(evaluate_action(run,'target_read_only_request','x.api.example.com',now=now).decision,'deny')
        self.assertEqual(evaluate_action(run,'target_read_only_request','blocked.example.com',now=now).decision,'deny')
        self.assertEqual(evaluate_action(run,'target_enumeration','api.example.com',now=now).decision,'deny')
        ev=revoke_approval(run,g.approval_id,'authorized-operator','Approval withdrawn',now=now+timedelta(minutes=1))
        self.assertEqual(ev.event_type,'approval_revoked')
        self.assertEqual(list_approvals(run,now+timedelta(minutes=2)).approvals[0].status,'revoked')
        self.assertEqual(evaluate_action(run,'target_read_only_request','api.example.com',now=now+timedelta(minutes=2)).decision,'deny')
        g2=grant_approval(run,'target_read_only_request','api.example.com','authorized-operator','again',duration_minutes=1,now=now+timedelta(minutes=3))
        self.assertEqual(list_approvals(run,now+timedelta(minutes=5)).approvals[-1].status,'expired')
        self.assertEqual(evaluate_action(run,'local_analysis',now=now).decision,'allow')
        self.assertEqual(evaluate_action(run,'public_source_lookup','api.example.com',now=now).decision,'allow')
        for a in PROHIBITED:
            self.assertEqual(evaluate_action(run,a,'api.example.com',now=now).decision,'deny')
            with self.assertRaises(ApprovalPolicyError): grant_approval(run,a,'api.example.com','authorized-operator','x',duration_minutes=1,now=now)
    def test_validation_and_missing_registry(self):
        tmp, run = self.make_run(); self.addCleanup(tmp.cleanup)
        (run/'approvals.jsonl').unlink()
        self.assertEqual(list_approvals(run).approval_count,0)
        with self.assertRaises(ApprovalPolicyError): grant_approval(run,'local_analysis','api.example.com','authorized-operator','x',duration_minutes=1)
        with self.assertRaises(ApprovalValidationError): grant_approval(run,'target_read_only_request','http://u:p@api.example.com','authorized-operator','x',duration_minutes=1)
        g=grant_approval(run,'target_read_only_request','api.example.com','authorized-operator','x',duration_minutes=1,now=datetime(2026,1,1,tzinfo=timezone.utc))
        with self.assertRaises(ApprovalPolicyError): grant_approval(run,'target_read_only_request','api.example.com','authorized-operator','x',duration_minutes=1,now=datetime(2026,1,1,tzinfo=timezone.utc))
        with self.assertRaises(ApprovalPolicyError): revoke_approval(run,g.approval_id,'authorized-operator','too late',now=datetime(2026,1,2,tzinfo=timezone.utc))
        (run/'approvals.jsonl').write_text('{bad\n')
        with self.assertRaises(ApprovalValidationError): list_approvals(run)
    def test_state_restrictions_and_scope_changes(self):
        tmp, run = self.make_run(); self.addCleanup(tmp.cleanup)
        now=datetime(2026,1,1,tzinfo=timezone.utc)
        g=grant_approval(run,'target_read_only_request','api.example.com','authorized-operator','x',duration_minutes=60,now=now)
        (run/'scope.yaml').write_text('in_scope:\n  - example.com\nout_of_scope: []\n')
        self.assertEqual(evaluate_action(run,'target_read_only_request','api.example.com',now=now).decision,'deny')
        self.assertEqual((run/'approvals.jsonl').read_text().count('\n'),1)

if __name__ == '__main__': unittest.main()
