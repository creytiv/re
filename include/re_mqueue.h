/**
 * @file re_mqueue.h Thread Safe Message Queue
 *
 * Copyright (C) 2010 Creytiv.com
 */

struct mqueue;

typedef void (mqueue_h)(int id, void *data);

int mqueue_alloc(struct mqueue **mqp);
int mqueue_push(struct mqueue *mq, mqueue_h *h, int id, void *data);
