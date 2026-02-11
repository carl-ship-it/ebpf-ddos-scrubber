import React, { useState } from 'react';
import {
  Card,
  Row,
  Col,
  Table,
  Tag,
  Badge,
  Button,
  Modal,
  Form,
  Input,
  Select,
  Switch,
  Space,
  Statistic,
  Typography,
  message,
  Popconfirm,
} from 'antd';
import {
  PlusOutlined,
  SyncOutlined,
  CloudDownloadOutlined,
  SafetyOutlined,
  StopOutlined,
  DatabaseOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';

const { Text } = Typography;

// --------------- Types ---------------

interface ThreatFeed {
  key: string;
  name: string;
  url: string;
  type: 'plaintext' | 'csv' | 'json';
  enabled: boolean;
  lastSync: string;
  entries: number;
  status: 'ok' | 'error' | 'syncing' | 'pending';
}

interface RecentBlock {
  key: string;
  ip: string;
  feedSource: string;
  threatType: string;
  confidence: number;
  action: string;
  time: string;
}

// --------------- Mock data ---------------

const initialFeeds: ThreatFeed[] = [
  {
    key: 'spamhaus-drop',
    name: 'Spamhaus DROP',
    url: 'https://www.spamhaus.org/drop/drop.txt',
    type: 'plaintext',
    enabled: true,
    lastSync: dayjs().subtract(12, 'minute').format('YYYY-MM-DD HH:mm:ss'),
    entries: 1247,
    status: 'ok',
  },
  {
    key: 'spamhaus-edrop',
    name: 'Spamhaus EDROP',
    url: 'https://www.spamhaus.org/drop/edrop.txt',
    type: 'plaintext',
    enabled: true,
    lastSync: dayjs().subtract(12, 'minute').format('YYYY-MM-DD HH:mm:ss'),
    entries: 482,
    status: 'ok',
  },
  {
    key: 'abuseipdb',
    name: 'AbuseIPDB',
    url: 'https://api.abuseipdb.com/api/v2/blacklist',
    type: 'json',
    enabled: true,
    lastSync: dayjs().subtract(1, 'hour').subtract(5, 'minute').format('YYYY-MM-DD HH:mm:ss'),
    entries: 8934,
    status: 'ok',
  },
  {
    key: 'custom',
    name: 'Custom Internal',
    url: 'https://soc.internal.corp/feeds/blocklist.csv',
    type: 'csv',
    enabled: false,
    lastSync: dayjs().subtract(3, 'day').format('YYYY-MM-DD HH:mm:ss'),
    entries: 156,
    status: 'error',
  },
];

const threatTypes = ['botnet', 'scanner', 'tor', 'proxy', 'malware'] as const;
const threatColors: Record<string, string> = {
  botnet: '#f5222d',
  scanner: '#fa8c16',
  tor: '#722ed1',
  proxy: '#faad14',
  malware: '#eb2f96',
};

function randomIP(): string {
  return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

const initialBlocks: RecentBlock[] = Array.from({ length: 10 }, (_, i) => {
  const feed = initialFeeds[Math.floor(Math.random() * 3)]; // only enabled ones
  const tt = threatTypes[Math.floor(Math.random() * threatTypes.length)];
  return {
    key: `block-${i}`,
    ip: randomIP(),
    feedSource: feed.name,
    threatType: tt,
    confidence: Math.floor(Math.random() * 40) + 60,
    action: 'DROP',
    time: dayjs()
      .subtract(Math.floor(Math.random() * 120), 'minute')
      .format('YYYY-MM-DD HH:mm:ss'),
  };
}).sort((a, b) => (a.time > b.time ? -1 : 1));

// --------------- Component ---------------

const ThreatIntel: React.FC = () => {
  const [feeds, setFeeds] = useState<ThreatFeed[]>(initialFeeds);
  const [blocks] = useState<RecentBlock[]>(initialBlocks);
  const [modalOpen, setModalOpen] = useState(false);
  const [form] = Form.useForm();

  // Computed stats
  const totalEntries = feeds.reduce((sum, f) => sum + (f.enabled ? f.entries : 0), 0);
  const activeFeeds = feeds.filter((f) => f.enabled).length;
  const lastSyncTime = feeds
    .filter((f) => f.enabled)
    .map((f) => f.lastSync)
    .sort()
    .pop() ?? '--';

  // --------------- Handlers ---------------

  const handleAddFeed = async () => {
    try {
      const values = await form.validateFields();
      const newFeed: ThreatFeed = {
        key: `feed-${Date.now()}`,
        name: values.name,
        url: values.url,
        type: values.type,
        enabled: true,
        lastSync: '--',
        entries: 0,
        status: 'pending',
      };
      setFeeds((prev) => [...prev, newFeed]);
      setModalOpen(false);
      form.resetFields();
      message.success(`Feed "${values.name}" added`);
    } catch {
      // validation error
    }
  };

  const handleToggle = (key: string, checked: boolean) => {
    setFeeds((prev) =>
      prev.map((f) => (f.key === key ? { ...f, enabled: checked } : f)),
    );
  };

  const handleSync = (key: string) => {
    setFeeds((prev) =>
      prev.map((f) =>
        f.key === key ? { ...f, status: 'syncing' as const } : f,
      ),
    );
    setTimeout(() => {
      setFeeds((prev) =>
        prev.map((f) =>
          f.key === key
            ? {
                ...f,
                status: 'ok' as const,
                lastSync: dayjs().format('YYYY-MM-DD HH:mm:ss'),
                entries: f.entries + Math.floor(Math.random() * 50),
              }
            : f,
        ),
      );
      message.success('Feed synced');
    }, 1500);
  };

  const handleSyncAll = () => {
    feeds
      .filter((f) => f.enabled)
      .forEach((f) => handleSync(f.key));
  };

  const handleRemoveFeed = (key: string) => {
    setFeeds((prev) => prev.filter((f) => f.key !== key));
    message.success('Feed removed');
  };

  // --------------- Feed table columns ---------------

  const feedColumns: ColumnsType<ThreatFeed> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name: string) => <Text strong style={{ color: 'rgba(255,255,255,0.85)' }}>{name}</Text>,
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      ellipsis: true,
      render: (url: string) => (
        <Text style={{ color: 'rgba(255,255,255,0.45)', fontFamily: 'monospace', fontSize: 12 }}>
          {url}
        </Text>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      render: (t: string) => {
        const colors: Record<string, string> = { plaintext: 'blue', csv: 'cyan', json: 'green' };
        return <Tag color={colors[t] ?? 'default'}>{t.toUpperCase()}</Tag>;
      },
    },
    {
      title: 'Enabled',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 80,
      render: (enabled: boolean, record: ThreatFeed) => (
        <Switch
          checked={enabled}
          size="small"
          onChange={(checked) => handleToggle(record.key, checked)}
        />
      ),
    },
    {
      title: 'Last Sync',
      dataIndex: 'lastSync',
      key: 'lastSync',
      width: 170,
      render: (v: string) => (
        <Text style={{ color: 'rgba(255,255,255,0.45)', fontFamily: 'monospace', fontSize: 12 }}>{v}</Text>
      ),
    },
    {
      title: 'Entries',
      dataIndex: 'entries',
      key: 'entries',
      width: 80,
      render: (v: number) => (
        <Text style={{ color: 'rgba(255,255,255,0.85)', fontFamily: 'monospace' }}>
          {v.toLocaleString()}
        </Text>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: ThreatFeed['status']) => {
        if (status === 'ok') return <Badge status="success" text={<Text style={{ color: '#52c41a' }}>OK</Text>} />;
        if (status === 'syncing') return <Badge status="processing" text={<Text style={{ color: '#1668dc' }}>Syncing</Text>} />;
        if (status === 'error') return <Badge status="error" text={<Text style={{ color: '#f5222d' }}>Error</Text>} />;
        return <Badge status="default" text={<Text style={{ color: 'rgba(255,255,255,0.45)' }}>Pending</Text>} />;
      },
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 160,
      render: (_: unknown, record: ThreatFeed) => (
        <Space>
          <Button
            size="small"
            icon={<SyncOutlined spin={record.status === 'syncing'} />}
            onClick={() => handleSync(record.key)}
            disabled={!record.enabled || record.status === 'syncing'}
          >
            Sync
          </Button>
          <Popconfirm title="Remove this feed?" onConfirm={() => handleRemoveFeed(record.key)}>
            <Button size="small" danger>
              Remove
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  // --------------- Recent blocks columns ---------------

  const blockColumns: ColumnsType<RecentBlock> = [
    {
      title: 'IP Address',
      dataIndex: 'ip',
      key: 'ip',
      render: (ip: string) => (
        <Text style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.85)' }}>{ip}</Text>
      ),
    },
    {
      title: 'Feed Source',
      dataIndex: 'feedSource',
      key: 'feedSource',
    },
    {
      title: 'Threat Type',
      dataIndex: 'threatType',
      key: 'threatType',
      render: (tt: string) => (
        <Tag color={threatColors[tt] ?? 'default'} style={{ textTransform: 'capitalize' }}>
          {tt}
        </Tag>
      ),
    },
    {
      title: 'Confidence',
      dataIndex: 'confidence',
      key: 'confidence',
      width: 100,
      render: (c: number) => {
        let color = '#52c41a';
        if (c >= 80) color = '#f5222d';
        else if (c >= 60) color = '#faad14';
        return <Text style={{ color, fontFamily: 'monospace' }}>{c}%</Text>;
      },
    },
    {
      title: 'Action',
      dataIndex: 'action',
      key: 'action',
      width: 80,
      render: (a: string) => <Tag color="red">{a}</Tag>,
    },
    {
      title: 'Time',
      dataIndex: 'time',
      key: 'time',
      width: 170,
      render: (t: string) => (
        <Text style={{ color: 'rgba(255,255,255,0.45)', fontFamily: 'monospace', fontSize: 12 }}>{t}</Text>
      ),
    },
  ];

  // --------------- Render ---------------

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <SafetyOutlined style={{ fontSize: 18, color: '#1668dc' }} />
        <Text strong style={{ fontSize: 16, color: 'rgba(255,255,255,0.85)' }}>
          Threat Intelligence Feeds
        </Text>
      </div>

      {/* Stats Row */}
      <Row gutter={[12, 12]}>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="Total Entries"
              value={totalEntries}
              prefix={<DatabaseOutlined />}
              valueStyle={{ color: '#1668dc', fontFamily: 'monospace' }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="Total Drops"
              value={23847}
              prefix={<StopOutlined />}
              valueStyle={{ color: '#f5222d', fontFamily: 'monospace' }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="Active Feeds"
              value={activeFeeds}
              suffix={`/ ${feeds.length}`}
              prefix={<CloudDownloadOutlined />}
              valueStyle={{ color: '#52c41a', fontFamily: 'monospace' }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="Last Sync"
              value={lastSyncTime}
              prefix={<ClockCircleOutlined />}
              valueStyle={{ fontSize: 14, fontFamily: 'monospace' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Feed Management */}
      <Card
        title="Feed Management"
        size="small"
        extra={
          <Space>
            <Button
              icon={<SyncOutlined />}
              size="small"
              onClick={handleSyncAll}
            >
              Sync All
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              size="small"
              onClick={() => setModalOpen(true)}
            >
              Add Feed
            </Button>
          </Space>
        }
      >
        <Table
          columns={feedColumns}
          dataSource={feeds}
          rowKey="key"
          size="small"
          pagination={false}
        />
      </Card>

      {/* Recent Blocks */}
      <Card title="Recent Threat Intel Blocks" size="small">
        <Table
          columns={blockColumns}
          dataSource={blocks}
          rowKey="key"
          size="small"
          pagination={{ pageSize: 10, size: 'small' }}
        />
      </Card>

      {/* Add Feed Modal */}
      <Modal
        title="Add Threat Intelligence Feed"
        open={modalOpen}
        onOk={handleAddFeed}
        onCancel={() => setModalOpen(false)}
        okText="Add Feed"
        width={520}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="name"
            label="Feed Name"
            rules={[{ required: true, message: 'Please enter a feed name' }]}
          >
            <Input placeholder="e.g. Emerging Threats" />
          </Form.Item>
          <Form.Item
            name="url"
            label="Feed URL"
            rules={[
              { required: true, message: 'Please enter the feed URL' },
              { type: 'url', message: 'Please enter a valid URL' },
            ]}
          >
            <Input placeholder="https://example.com/blocklist.txt" />
          </Form.Item>
          <Form.Item
            name="type"
            label="Format"
            rules={[{ required: true, message: 'Please select a format' }]}
            initialValue="plaintext"
          >
            <Select
              options={[
                { label: 'Plaintext (one IP/CIDR per line)', value: 'plaintext' },
                { label: 'CSV', value: 'csv' },
                { label: 'JSON', value: 'json' },
              ]}
            />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default ThreatIntel;
