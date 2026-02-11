import React, { useState, useMemo, useCallback } from 'react';
import {
  Card,
  Table,
  Row,
  Col,
  Statistic,
  Switch,
  Select,
  Button,
  Tag,
  Space,
  Typography,
  Upload,
  message,
  Popconfirm,
  Tooltip,
} from 'antd';
import {
  GlobalOutlined,
  StopOutlined,
  CheckCircleOutlined,
  UploadOutlined,
  WarningOutlined,
  EyeOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { formatCount } from '../utils';

const { Text } = Typography;

// --- Types ---

type GeoAction = 'pass' | 'drop' | 'rate_limit' | 'monitor';

interface CountryEntry {
  code: string;
  name: string;
  flag: string;
  action: GeoAction;
  packets: number;
  drops: number;
}

// --- Country seed data ---

const COUNTRY_SEED: Omit<CountryEntry, 'action' | 'packets' | 'drops'>[] = [
  { code: 'US', name: 'United States', flag: '\u{1F1FA}\u{1F1F8}' },
  { code: 'CN', name: 'China', flag: '\u{1F1E8}\u{1F1F3}' },
  { code: 'RU', name: 'Russia', flag: '\u{1F1F7}\u{1F1FA}' },
  { code: 'DE', name: 'Germany', flag: '\u{1F1E9}\u{1F1EA}' },
  { code: 'BR', name: 'Brazil', flag: '\u{1F1E7}\u{1F1F7}' },
  { code: 'IN', name: 'India', flag: '\u{1F1EE}\u{1F1F3}' },
  { code: 'KR', name: 'South Korea', flag: '\u{1F1F0}\u{1F1F7}' },
  { code: 'JP', name: 'Japan', flag: '\u{1F1EF}\u{1F1F5}' },
  { code: 'FR', name: 'France', flag: '\u{1F1EB}\u{1F1F7}' },
  { code: 'GB', name: 'United Kingdom', flag: '\u{1F1EC}\u{1F1E7}' },
  { code: 'NL', name: 'Netherlands', flag: '\u{1F1F3}\u{1F1F1}' },
  { code: 'UA', name: 'Ukraine', flag: '\u{1F1FA}\u{1F1E6}' },
  { code: 'VN', name: 'Vietnam', flag: '\u{1F1FB}\u{1F1F3}' },
  { code: 'TW', name: 'Taiwan', flag: '\u{1F1F9}\u{1F1FC}' },
  { code: 'ID', name: 'Indonesia', flag: '\u{1F1EE}\u{1F1E9}' },
  { code: 'TH', name: 'Thailand', flag: '\u{1F1F9}\u{1F1ED}' },
  { code: 'PL', name: 'Poland', flag: '\u{1F1F5}\u{1F1F1}' },
  { code: 'CA', name: 'Canada', flag: '\u{1F1E8}\u{1F1E6}' },
  { code: 'AU', name: 'Australia', flag: '\u{1F1E6}\u{1F1FA}' },
  { code: 'IT', name: 'Italy', flag: '\u{1F1EE}\u{1F1F9}' },
  { code: 'SG', name: 'Singapore', flag: '\u{1F1F8}\u{1F1EC}' },
  { code: 'HK', name: 'Hong Kong', flag: '\u{1F1ED}\u{1F1F0}' },
  { code: 'RO', name: 'Romania', flag: '\u{1F1F7}\u{1F1F4}' },
  { code: 'AR', name: 'Argentina', flag: '\u{1F1E6}\u{1F1F7}' },
  { code: 'ZA', name: 'South Africa', flag: '\u{1F1FF}\u{1F1E6}' },
  { code: 'MX', name: 'Mexico', flag: '\u{1F1F2}\u{1F1FD}' },
  { code: 'TR', name: 'Turkey', flag: '\u{1F1F9}\u{1F1F7}' },
  { code: 'PH', name: 'Philippines', flag: '\u{1F1F5}\u{1F1ED}' },
  { code: 'BD', name: 'Bangladesh', flag: '\u{1F1E7}\u{1F1E9}' },
  { code: 'IR', name: 'Iran', flag: '\u{1F1EE}\u{1F1F7}' },
];

// Known high-attack-volume country codes (used by "Block High-Risk" action)
const HIGH_RISK_CODES = new Set(['CN', 'RU', 'VN', 'UA', 'BR', 'ID', 'IR', 'BD', 'RO', 'TH']);

// --- Mock helpers ---

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateMockCountries(): CountryEntry[] {
  return COUNTRY_SEED.map((c) => {
    const packets = randomInt(500, 5_000_000);
    const drops = randomInt(0, Math.floor(packets * 0.4));
    const action: GeoAction = HIGH_RISK_CODES.has(c.code)
      ? (['drop', 'rate_limit', 'monitor'] as const)[randomInt(0, 2)]
      : 'pass';
    return { ...c, action, packets, drops };
  });
}

// --- Action colours & labels ---

const ACTION_META: Record<GeoAction, { color: string; label: string }> = {
  pass: { color: 'green', label: 'Pass' },
  drop: { color: 'red', label: 'Drop' },
  rate_limit: { color: 'orange', label: 'Rate Limit' },
  monitor: { color: 'blue', label: 'Monitor' },
};

// --- Component ---

const GeoIPPage: React.FC = () => {
  const [geoEnabled, setGeoEnabled] = useState(true);
  const [countries, setCountries] = useState<CountryEntry[]>(generateMockCountries);

  // Derived stats
  const stats = useMemo(() => {
    let totalDrops = 0;
    let blocked = 0;
    let rateLimited = 0;
    let monitored = 0;
    for (const c of countries) {
      totalDrops += c.drops;
      if (c.action === 'drop') blocked++;
      if (c.action === 'rate_limit') rateLimited++;
      if (c.action === 'monitor') monitored++;
    }
    return { totalDrops, blocked, rateLimited, monitored };
  }, [countries]);

  // Action handlers
  const handleActionChange = useCallback(
    (code: string, action: GeoAction) => {
      setCountries((prev) =>
        prev.map((c) => (c.code === code ? { ...c, action } : c)),
      );
      const meta = ACTION_META[action];
      message.success(`${code} policy set to ${meta.label}`);
    },
    [],
  );

  const handleBlockHighRisk = useCallback(() => {
    setCountries((prev) =>
      prev.map((c) =>
        HIGH_RISK_CODES.has(c.code) ? { ...c, action: 'drop' as GeoAction } : c,
      ),
    );
    message.success(`${HIGH_RISK_CODES.size} high-risk countries set to Drop`);
  }, []);

  const handleAllowAll = useCallback(() => {
    setCountries((prev) => prev.map((c) => ({ ...c, action: 'pass' as GeoAction })));
    message.info('All countries set to Pass');
  }, []);

  // Table columns
  const columns: ColumnsType<CountryEntry> = [
    {
      title: 'Country',
      key: 'country',
      width: 240,
      sorter: (a, b) => a.name.localeCompare(b.name),
      render: (_, record) => (
        <Space>
          <span style={{ fontSize: 18 }}>{record.flag}</span>
          <Text strong style={{ color: 'rgba(255,255,255,0.85)' }}>
            {record.code}
          </Text>
          <Text style={{ color: 'rgba(255,255,255,0.55)' }}>{record.name}</Text>
        </Space>
      ),
    },
    {
      title: 'Action',
      key: 'action',
      width: 160,
      filters: [
        { text: 'Pass', value: 'pass' },
        { text: 'Drop', value: 'drop' },
        { text: 'Rate Limit', value: 'rate_limit' },
        { text: 'Monitor', value: 'monitor' },
      ],
      onFilter: (value, record) => record.action === value,
      render: (_, record) => (
        <Select
          value={record.action}
          onChange={(val) => handleActionChange(record.code, val)}
          size="small"
          style={{ width: 130 }}
          disabled={!geoEnabled}
          options={[
            { value: 'pass', label: 'Pass' },
            { value: 'drop', label: 'Drop' },
            { value: 'rate_limit', label: 'Rate Limit' },
            { value: 'monitor', label: 'Monitor' },
          ]}
        />
      ),
    },
    {
      title: 'Packets',
      dataIndex: 'packets',
      key: 'packets',
      width: 120,
      sorter: (a, b) => a.packets - b.packets,
      defaultSortOrder: 'descend',
      render: (val: number) => (
        <Text style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.85)' }}>
          {formatCount(val)}
        </Text>
      ),
    },
    {
      title: 'Drops',
      dataIndex: 'drops',
      key: 'drops',
      width: 120,
      sorter: (a, b) => a.drops - b.drops,
      render: (val: number) => (
        <Text style={{ fontFamily: 'monospace', color: val > 0 ? '#f5222d' : 'rgba(255,255,255,0.45)' }}>
          {formatCount(val)}
        </Text>
      ),
    },
    {
      title: 'Status',
      key: 'status',
      width: 110,
      render: (_, record) => {
        const meta = ACTION_META[record.action];
        return <Tag color={meta.color}>{meta.label}</Tag>;
      },
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Stats row */}
      <Row gutter={[12, 12]}>
        <Col xs={12} sm={6}>
          <Card size="small">
            <Statistic
              title="Total GeoIP Drops"
              value={stats.totalDrops}
              valueStyle={{ color: '#f5222d', fontSize: 22 }}
              prefix={<StopOutlined />}
              formatter={(val) => formatCount(val as number)}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small">
            <Statistic
              title="Countries Blocked"
              value={stats.blocked}
              valueStyle={{ color: '#f5222d', fontSize: 22 }}
              prefix={<StopOutlined />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small">
            <Statistic
              title="Countries Rate-Limited"
              value={stats.rateLimited}
              valueStyle={{ color: '#fa8c16', fontSize: 22 }}
              prefix={<WarningOutlined />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small">
            <Statistic
              title="Countries Monitored"
              value={stats.monitored}
              valueStyle={{ color: '#1668dc', fontSize: 22 }}
              prefix={<EyeOutlined />}
            />
          </Card>
        </Col>
      </Row>

      {/* Country table card */}
      <Card
        title={
          <Space>
            <GlobalOutlined style={{ color: '#1668dc' }} />
            <span>GeoIP Country Policy</span>
          </Space>
        }
        extra={
          <Space>
            <Text style={{ color: 'rgba(255,255,255,0.65)', marginRight: 4 }}>
              CFG_GEOIP_ENABLE
            </Text>
            <Switch
              checked={geoEnabled}
              onChange={(checked) => {
                setGeoEnabled(checked);
                message.info(checked ? 'GeoIP filtering enabled' : 'GeoIP filtering disabled');
              }}
              checkedChildren="ON"
              unCheckedChildren="OFF"
            />
          </Space>
        }
      >
        {/* Quick action buttons */}
        <div style={{ marginBottom: 16, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <Popconfirm
            title="Block high-risk countries?"
            description={`This will set ${HIGH_RISK_CODES.size} countries (CN, RU, VN, UA, BR, ID, IR, BD, RO, TH) to Drop.`}
            onConfirm={handleBlockHighRisk}
            okText="Confirm"
            disabled={!geoEnabled}
          >
            <Button
              type="primary"
              danger
              icon={<StopOutlined />}
              disabled={!geoEnabled}
            >
              Block High-Risk
            </Button>
          </Popconfirm>

          <Popconfirm
            title="Allow all countries?"
            description="This will reset all country policies to Pass."
            onConfirm={handleAllowAll}
            okText="Confirm"
            disabled={!geoEnabled}
          >
            <Button
              icon={<CheckCircleOutlined />}
              disabled={!geoEnabled}
            >
              Allow All
            </Button>
          </Popconfirm>

          <Tooltip title="Import a MaxMind GeoLite2 database (placeholder)">
            <Upload
              accept=".mmdb,.tar.gz"
              showUploadList={false}
              beforeUpload={() => {
                message.info('GeoLite2 import is not yet implemented');
                return false;
              }}
            >
              <Button icon={<UploadOutlined />} disabled={!geoEnabled}>
                Import GeoLite2 DB
              </Button>
            </Upload>
          </Tooltip>
        </div>

        <Table
          columns={columns}
          dataSource={countries}
          rowKey="code"
          size="small"
          pagination={{ pageSize: 15, showSizeChanger: true, pageSizeOptions: ['15', '30', '50'] }}
          rowClassName={(record) =>
            record.action === 'drop'
              ? 'geo-row-drop'
              : record.action === 'rate_limit'
                ? 'geo-row-rl'
                : ''
          }
          style={{ opacity: geoEnabled ? 1 : 0.45, pointerEvents: geoEnabled ? 'auto' : 'none' }}
        />
      </Card>

      {/* Inline styles for row highlighting */}
      <style>{`
        .geo-row-drop td {
          background: rgba(245, 34, 45, 0.06) !important;
        }
        .geo-row-rl td {
          background: rgba(250, 140, 22, 0.06) !important;
        }
      `}</style>
    </div>
  );
};

export default GeoIPPage;
