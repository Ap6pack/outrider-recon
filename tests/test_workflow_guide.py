import tempfile, unittest
from pathlib import Path

from outrider.run_setup import WebRunRequest, create_web_run_atomic
from outrider.state import transition_state
from outrider.workflow_guide import build_workflow_guide

class WorkflowGuideTests(unittest.TestCase):
    def make_run(self):
        td=tempfile.TemporaryDirectory(); self.addCleanup(td.cleanup)
        run=create_web_run_atomic(Path(td.name), WebRunRequest('example.com','tester','auth',['example.com'],[], 'HackerOne', None))
        return run
    def test_initialized_guide(self):
        run=self.make_run(); g=build_workflow_guide(run,enrichment_enabled=False)
        self.assertEqual(g['phase']['label'],'Setup')
        self.assertEqual(g['next_action']['id'],'review_scope')
        self.assertEqual([p['label'] for p in g['progress']], ['Setup','Scope','Discovery','Evidence','Analysis','Findings','Complete'])
        self.assertNotIn('authorization_reference', str(g)); self.assertNotIn('X-', str(g))
    def test_scoped_and_collecting_without_enrichment(self):
        run=self.make_run(); transition_state(run,'scoped','tester')
        g=build_workflow_guide(run,enrichment_enabled=False)
        self.assertEqual(g['next_action']['id'],'begin_discovery')
        transition_state(run,'collecting','tester')
        g=build_workflow_guide(run,enrichment_enabled=False)
        self.assertEqual(g['next_action']['id'],'discovery_setup')
    def test_collecting_with_enrichment(self):
        run=self.make_run(); transition_state(run,'scoped','tester'); transition_state(run,'collecting','tester')
        self.assertEqual(build_workflow_guide(run,enrichment_enabled=True)['next_action']['id'],'open_discovery')
    def test_revision_deterministic_and_changes(self):
        run=self.make_run(); a=build_workflow_guide(run,enrichment_enabled=False)['guide_revision']; b=build_workflow_guide(run,enrichment_enabled=False)['guide_revision']
        self.assertEqual(a,b)
        transition_state(run,'scoped','tester')
        self.assertNotEqual(a, build_workflow_guide(run,enrichment_enabled=False)['guide_revision'])
    def test_terminal_states(self):
        for state,label in [('completed','Engagement Completed'),('cancelled','Engagement Cancelled'),('archived','Engagement Archived')]:
            run=self.make_run()
            if state=='completed':
                for s in ['scoped','collecting','analyzing','reporting','completed']: transition_state(run,s,'tester')
            elif state=='cancelled': transition_state(run,'cancelled','tester','stop')
            else:
                for s in ['scoped','collecting','analyzing','reporting','completed','archived']: transition_state(run,s,'tester')
            self.assertEqual(build_workflow_guide(run,enrichment_enabled=False)['next_action']['label'], label)

if __name__=='__main__': unittest.main()
