/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <errno.h>
#include <stdint.h>

#include "ret_mp.h"

int ret_mp_skip(mpack_reader_t *r)
{
	/* remaining[d]: values still to skip at nesting depth d. */
	uint64_t remaining[RET_MP_MAX_DEPTH + 1];
	int depth = 0;

	remaining[0] = 1;
	while (depth >= 0) {
		if (remaining[depth] == 0) {
			depth--;
			continue;
		}
		remaining[depth]--;

		mpack_tag_t tag = mpack_read_tag(r);

		if (mpack_reader_error(r) != mpack_ok) {
			return -EBADMSG;
		}

		switch (mpack_tag_type(&tag)) {
		case mpack_type_str:
		case mpack_type_bin:
			mpack_skip_bytes(r, mpack_tag_bytes(&tag));
			break;
		case mpack_type_array:
		case mpack_type_map: {
			uint64_t n = mpack_tag_type(&tag) == mpack_type_array
					     ? mpack_tag_array_count(&tag)
					     : 2ULL * mpack_tag_map_count(&tag);

			if (n == 0) {
				break;
			}
			if (depth + 1 > RET_MP_MAX_DEPTH) {
				return -EBADMSG;
			}
			remaining[++depth] = n;
			break;
		}
		default:
			/* Scalars are fully consumed by mpack_read_tag(). */
			break;
		}
		if (mpack_reader_error(r) != mpack_ok) {
			return -EBADMSG;
		}
	}
	return 0;
}
