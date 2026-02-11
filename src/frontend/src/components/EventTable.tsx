import React, { useState } from 'react';
import { Table, Tag, Select, Space, Button, Badge } from 'antd';
import { ClearOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';
import { useEvents } from '../hooks/useEvents';
import { useStore } from '../store';
import { protoName } from '../utils';
import { ATTACK_COLORS } from '../styles/theme';
import type { ScrubberEvent } from '../types';

const actionColors: Record<string, string> = {
  DROP: 'red',
  PASS: 'green',
};

const columns: ColumnsType<ScrubberEvent> = [
  {
    title: 'Time',
    dataIndex: 'timestampNs',
    key: 'time',
    width: 100,
    render: (ns: number) => dayjs(ns / 1e6).format('HH:mm:ss'),
  },
  {
    title: 'Action',
    dataIndex: 'action',
    key: 'action',
    width: 80,
    render: (action: string) => (
      <Tag color={actionColors[action] || 'default'}>{action}</Tag>
    ),
  },
  {
    title: 'Attack Type',
    dataIndex: 'attackType',
    key: 'attackType',
    width: 140,
    render: (type: string) => (
      <Badge
        color={ATTACK_COLORS[type] || '#999'}
        text={<span style={{ color: 'rgba(255,255,255,0.85)' }}>{type.replace(/_/g, ' ')}</span>}
      />
    ),
  },
  {
    title: 'Proto',
    dataIndex: 'protocol',
    key: 'protocol',
    width: 70,
    render: (proto: number) => protoName(proto),
  },
  {
    title: 'Source',
    key: 'source',
    width: 180,
    render: (_: unknown, record: ScrubberEvent) =>
      `${record.srcIp}:${record.srcPort}`,
  },
  {
    title: 'Destination',
    key: 'destination',
    width: 180,
    render: (_: unknown, record: ScrubberEvent) =>
      `${record.dstIp}:${record.dstPort}`,
  },
  {
    title: 'Reason',
    dataIndex: 'dropReason',
    key: 'dropReason',
    width: 120,
    render: (reason: string) => (
      <span style={{ color: 'rgba(255,255,255,0.65)' }}>
        {reason.replace(/_/g, ' ')}
      </span>
    ),
  },
];

interface Props {
  maxRows?: number;
  compact?: boolean;
}

const EventTable: React.FC<Props> = ({ maxRows = 100, compact = false }) => {
  const [attackFilter, setAttackFilter] = useState<string | undefined>();
  const clearEvents = useStore((s) => s.clearEvents);

  const events = useEvents(
    attackFilter ? { attackType: attackFilter } : undefined,
  );

  const displayed = events.slice(0, maxRows);

  const attackTypes = [
    'syn_flood',
    'udp_flood',
    'icmp_flood',
    'ack_flood',
    'dns_amplification',
    'ntp_amplification',
    'fragment',
  ];

  return (
    <div>
      {!compact && (
        <Space style={{ marginBottom: 12 }}>
          <Select
            allowClear
            placeholder="Filter by attack type"
            style={{ width: 200 }}
            value={attackFilter}
            onChange={setAttackFilter}
            options={attackTypes.map((t) => ({
              label: t.replace(/_/g, ' '),
              value: t,
            }))}
          />
          <Button icon={<ClearOutlined />} onClick={clearEvents}>
            Clear
          </Button>
          <span style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>
            {events.length} events
          </span>
        </Space>
      )}

      <Table
        columns={compact ? columns.slice(0, 5) : columns}
        dataSource={displayed}
        rowKey={(_, idx) => String(idx)}
        size="small"
        pagination={compact ? false : { pageSize: 20, showSizeChanger: true }}
        scroll={{ x: compact ? undefined : 900 }}
      />
    </div>
  );
};

export default EventTable;
