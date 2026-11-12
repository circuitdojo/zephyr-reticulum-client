# CI on Forgejo

ret-client's CI runs on the shared self-hosted Forgejo runner
(`jared@bigbox.local`), set up the same way as lion-client's (see that repo's
`docs/ci-forgejo.md` for the reasoning behind the container, volumes and
copied checkout).

`.forgejo/workflows/ci.yml` runs on every push to `main` and every pull
request. One job, `native_sim`, in the `ret-client-ci` container:

1. `west init -l --mf west-vanilla.yml` / `west update` on a cached volume, then
   `west patch apply` (`zephyr/patches.yml`; `west patch clean` first undoes the last run's)
2. Python checks in `tools/rns_peer`: ruff, and regenerating
   `tests/common/vectors_rns.h` from the pinned RNS and diffing it
3. Unit tests: `scripts/twister.sh -T tests -p native_sim`
4. `ret_basic` and `ret_lxmf` native_sim builds, failing on any compiler warning
5. `tools/run_e2e.sh`: every scenario against a real rnsd and the RNS test
   peer, inside the container (ports and AF_UNIX sockets stay local to it).
   On failure the device, peer and rnsd logs are printed.

Then the `nrf9151` job (needs `native_sim`), in the NCS workspace
(`west-ncs.yml`) on its own `ret-client-ncs-west` volume, with the same
`west patch clean` / `west update` / `west patch apply`. It builds
the samples for `circuitdojo_feather_nrf9151/nrf9151/ns` with sysbuild
(`ret_lora_gateway` with its `env/example.conf`, since it needs a hub host)
and fails on compiler warnings. It uploads `ret_basic`'s and `ret_lxmf`'s
`tfm_merged.hex` (TF-M plus app) together with nfed's
`uicr_debug_access_open.hex` as the `samples-nrf9151` artifact (14 days).
Flash both (`scripts/flash.py` does, from a build directory): without the UICR
image an erased nRF91 protects its debug port after the first reset.
Its first run on a cold volume clones all of NCS and takes the better part
of an hour.

## Runner setup (once, on bigbox.local)

1. Build the image (not built by any workflow). Its tag names the Zephyr
   SDK it carries (`zsdk-<ZSDK_VERSION>` from `ci/Dockerfile`), and
   `.forgejo/workflows/ci.yml` names that tag. A change that moves to a new
   SDK builds a new tag and points its workflow there, so `main` keeps its
   image until the change merges:

   ```bash
   git clone https://forgejo.internal.circuitdojo.com/circuitdojo/ret-client.git
   cd ret-client && docker build -t ret-client-ci:zsdk-1.0.1 ci/
   ```

2. Allowlist the volumes in the runner's `config.yml` (a missing entry is
   refused silently and every run starts from a cold workspace), then
   restart the runner:

   ```yaml
   container:
     valid_volumes:
       - ret-client-west
       - ret-client-ncs-west
       - ret-client-ccache
   ```

Changing a manifest file name or `self: path:` means wiping that workspace's
volume: `docker volume rm ret-client-west` (or `ret-client-ncs-west`).
