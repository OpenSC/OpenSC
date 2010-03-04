/*
 * muscle-filesystem.h: Support for MuscleCard Applet from musclecard.com 
 *
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <support@identityalliance.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef MUSCLE_FILESYSTEM_H
#define MUSCLE_FILESYSTEM_H

#include <stdlib.h>

#include "libopensc/types.h"

typedef struct msc_id {
	u8 id[4];
} msc_id;

typedef struct mscfs_file {
	msc_id objectId;
	size_t size;
	unsigned short read, write, delete;
	int ef;
} mscfs_file_t;

typedef struct mscfs_cache {
	int size;
	int totalSize;
	mscfs_file_t *array;
} mscfs_cache_t;

typedef struct mscsfs {
	u8 currentFile[2];
	u8 currentPath[2];
	int currentFileIndex;
	mscfs_cache_t cache;
	void* udata;
	int (*listFile)(mscfs_file_t *fileOut, int reset, void* udata);
} mscfs_t;

mscfs_t *mscfs_new(void);
void mscfs_free(mscfs_t *fs);
void mscfs_clear_cache(mscfs_t* fs);
int mscfs_push_file(mscfs_t* fs, mscfs_file_t *file);
int mscfs_update_cache(mscfs_t* fs);

void mscfs_check_cache(mscfs_t* fs);

int mscfs_lookup_path(mscfs_t* fs, const u8 *path, int pathlen, msc_id* objectId, int isDirectory);

int mscfs_lookup_local(mscfs_t* fs, const int id, msc_id* objectId);
/* -1 any, 0 DF, 1 EF */
int mscfs_check_selection(mscfs_t *fs, int requiredItem);
int mscfs_loadFileInfo(mscfs_t* fs, const u8 *path, int pathlen, mscfs_file_t **file_data, int* index);


#endif
