import React, { useState, useEffect } from 'react';
import { Card, Table, Tag, Progress, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { getTopAttackers } from '../mock/generator';
import { formatPPS, formatBPS, formatCount } from '../utils';

const { Text } = Typography;

interface Attacker {
  ip: string;
  country: string;
  asn: string;
  pps: number;
  bps: number;
  packets: number;
  blocked: number;
}

const FLAG: Record<string, string> = {
  CN: '🇨🇳', RU: '🇷🇺', US: '🇺🇸', BR: '🇧🇷', IN: '🇮🇳',
  VN: '🇻🇳', KR: '🇰🇷', DE: '🇩🇪', UA: '🇺🇦', ID: '🇮🇩',
};

const TopAttackers: React.FC = () => {
  const [data, setData] = useState<Attacker[]>([]);

  useEffect(() => {
    const iv = setInterval(() => setData(getTopAttackers()), 1000);
    setData(getTopAttackers());
    return () => clearInterval(iv);
  }, []);

  const maxPps = Math.max(...data.map((d) => d.pps), 1);

  const columns: ColumnsType<Attacker> = [
    {
      title: '#',
      key: 'rank',
      width: 36,
      render: (_v, _r, i) => (
        <Text style={{ color: i < 3 ? '#f5222d' : 'rgba(255,255,255,0.45)', fontWeight: i < 3 ? 700 : 400 }}>
          {i + 1}
        </Text>
      ),
    },
    {
      title: 'Source IP',
      dataIndex: 'ip',
      key: 'ip',
      width: 140,
      render: (ip: string, r: Attacker) => (
        <span>
          <Text code style={{ fontSize: 12 }}>{ip}</Text>
          <span style={{ marginLeft: 6, fontSize: 12 }}>{FLAG[r.country] || ''} {r.country}</span>
        </span>
      ),
    },
    {
      title: 'PPS',
      dataIndex: 'pps',
      key: 'pps',
      width: 160,
      sorter: (a, b) => a.pps - b.pps,
      defaultSortOrder: 'descend',
      render: (pps: number) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Progress
            percent={Math.round((pps / maxPps) * 100)}
            showInfo={false}
            strokeColor={pps / maxPps > 0.7 ? '#f5222d' : pps / maxPps > 0.3 ? '#fa8c16' : '#1668dc'}
            trailColor="#303030"
            size="small"
            style={{ flex: 1, marginBottom: 0 }}
          />
          <Text style={{ color: 'rgba(255,255,255,0.85)', fontSize: 12, minWidth: 60, textAlign: 'right' }}>
            {formatPPS(pps)}
          </Text>
        </div>
      ),
    },
    {
      title: 'BPS',
      dataIndex: 'bps',
      key: 'bps',
      width: 90,
      render: (bps: number) => <Text style={{ fontSize: 12, color: 'rgba(255,255,255,0.65)' }}>{formatBPS(bps)}</Text>,
    },
    {
      title: 'Blocked',
      dataIndex: 'blocked',
      key: 'blocked',
      width: 80,
      render: (b: number) => <Tag color="red" style={{ fontSize: 11 }}>{formatCount(b)}</Tag>,
    },
  ];

  return (
    <Card title="Top Attackers (Source IP)" size="small">
      <Table
        columns={columns}
        dataSource={data}
        rowKey="ip"
        size="small"
        pagination={false}
        scroll={{ y: 320 }}
      />
    </Card>
  );
};

export default TopAttackers;
