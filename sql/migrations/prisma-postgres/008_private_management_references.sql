ALTER TABLE public.ip_blocks ADD COLUMN management_id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE public.ip_blocks ADD CONSTRAINT ip_blocks_management_id_key UNIQUE(management_id);
ALTER TABLE public.account_blocks ADD COLUMN management_id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE public.account_blocks ADD CONSTRAINT account_blocks_management_id_key UNIQUE(management_id);
