-- Add verified static infrastructure modules; existing assets/results are preserved.
ALTER TABLE public.assessment_assets DROP CONSTRAINT assessment_assets_module_id_check;
ALTER TABLE public.assessment_assets ADD CONSTRAINT assessment_assets_module_id_check
 CHECK(module_id IN ('web.compare','linux.ssh','windows.policy','application.pe','application.apk','application.macho','application.package','virtualization.vmx','network.gns3'));
