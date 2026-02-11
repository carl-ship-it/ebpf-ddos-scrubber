import React, { useState } from 'react';
import {
  Card,
  Row,
  Col,
  Statistic,
  Switch,
  Select,
  Table,
  Tag,
  Space,
  Typography,
  Badge,
  Divider,
} from 'antd';
import {
  ApiOutlined,
  StopOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  SafetyOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import ReactECharts from 'echarts-for-react';
import { useStore } from '../store';

const { Text } = Typography;

// --------------- Types ---------------

interface ProtoViolation {
  key: string;
  protocol: string;
  violationType: string;
  srcIp: string;
  dstPort: number;
  count: number;
  action: string;
  lastSeen: string;
}

// --------------- Mock data ---------------

const violations: ProtoViolation[] = [
  { key: '1', protocol: 'DNS', violationType: 'Amplification response (QR=1, no query)', srcIp: '45.33.32.156', dstPort: 53, count: 12840, action: 'DROP', lastSeen: '2s ago' },
  { key: '2', protocol: 'NTP', violationType: 'Monlist request (mode 7)', srcIp: '198.51.100.12', dstPort: 123, count: 8421, action: 'DROP', lastSeen: '5s ago' },
  { key: '3', protocol: 'DNS', violationType: 'Oversized response (>512B, no EDNS)', srcIp: '203.0.113.88', dstPort: 53, count: 5200, action: 'DROP', lastSeen: '8s ago' },
  { key: '4', protocol: 'SSDP', violationType: 'M-SEARCH / NOTIFY reflection', srcIp: '192.0.2.45', dstPort: 1900, count: 3150, action: 'DROP', lastSeen: '12s ago' },
  { key: '5', protocol: 'Memcached', violationType: 'UDP amplification (port 11211)', srcIp: '100.24.56.78', dstPort: 11211, count: 2800, action: 'DROP', lastSeen: '15s ago' },
  { key: '6', protocol: 'TCP', violationType: 'Invalid state: SYN+ACK without SYN', srcIp: '172.16.0.99', dstPort: 443, count: 1920, action: 'DROP', lastSeen: '3s ago' },
  { key: '7', protocol: 'TCP', violationType: 'Sequence number out of window', srcIp: '10.0.5.22', dstPort: 80, count: 840, action: 'DROP', lastSeen: '20s ago' },
  { key: '8', protocol: 'DNS', violationType: 'Malformed query (qdcount=0)', srcIp: '91.200.12.3', dstPort: 53, count: 620, action: 'DROP', lastSeen: '30s ago' },
  { key: '9', protocol: 'NTP', violationType: 'Mode 6 control message (no conntrack)', srcIp: '185.244.25.10', dstPort: 123, count: 410, action: 'RATE_LIMIT', lastSeen: '45s ago' },
  { key: '10', protocol: 'TCP', violationType: 'RST flood (no established connection)', srcIp: '62.210.180.5', dstPort: 80, count: 380, action: 'DROP', lastSeen: '1m ago' },
];

// --------------- Component ---------------

const ProtoValidation: React.FC = () => {
  const stats = useStore((s) => s.currentStats);
  const [dnsMode, setDnsMode] = useState<number>(2);
  const [tcpStateCheck, setTcpStateCheck] = useState(true);
  const [ntpMonlistBlock, setNtpMonlistBlock] = useState(true);
  const [ssdpBlock, setSsdpBlock] = useState(true);
  const [memcachedBlock, setMemcachedBlock] = useState(true);

  // --------------- Chart ---------------

  const chartOption = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis' as const,
      backgroundColor: '#1f1f1f',
      borderColor: '#424242',
      textStyle: { color: 'rgba(255,255,255,0.85)' },
    },
    legend: {
      data: ['DNS', 'NTP', 'SSDP', 'Memcached', 'TCP State'],
      textStyle: { color: 'rgba(255,255,255,0.65)' },
      top: 0,
    },
    grid: { left: 60, right: 20, top: 40, bottom: 30 },
    xAxis: {
      type: 'category' as const,
      data: Array.from({ length: 30 }, (_, i) => `${30 - i}s`),
      axisLabel: { color: 'rgba(255,255,255,0.45)', fontSize: 10 },
      axisLine: { lineStyle: { color: '#424242' } },
    },
    yAxis: {
      type: 'value' as const,
      name: 'Drops/s',
      nameTextStyle: { color: 'rgba(255,255,255,0.45)' },
      axisLabel: { color: 'rgba(255,255,255,0.45)' },
      splitLine: { lineStyle: { color: '#303030' } },
    },
    series: [
      {
        name: 'DNS',
        type: 'bar',
        stack: 'total',
        data: Array.from({ length: 30 }, () => Math.floor(Math.random() * 200 + 100)),
        itemStyle: { color: '#722ed1' },
      },
      {
        name: 'NTP',
        type: 'bar',
        stack: 'total',
        data: Array.from({ length: 30 }, () => Math.floor(Math.random() * 150 + 50)),
        itemStyle: { color: '#fa8c16' },
      },
      {
        name: 'SSDP',
        type: 'bar',
        stack: 'total',
        data: Array.from({ length: 30 }, () => Math.floor(Math.random() * 80 + 20)),
        itemStyle: { color: '#13c2c2' },
      },
      {
        name: 'Memcached',
        type: 'bar',
        stack: 'total',
        data: Array.from({ length: 30 }, () => Math.floor(Math.random() * 60 + 10)),
        itemStyle: { color: '#eb2f96' },
      },
      {
        name: 'TCP State',
        type: 'bar',
        stack: 'total',
        data: Array.from({ length: 30 }, () => Math.floor(Math.random() * 120 + 30)),
        itemStyle: { color: '#1668dc' },
      },
    ],
  };

  // --------------- Table columns ---------------

  const columns: ColumnsType<ProtoViolation> = [
    {
      title: 'Protocol',
      dataIndex: 'protocol',
      key: 'protocol',
      width: 110,
      filters: [
        { text: 'DNS', value: 'DNS' },
        { text: 'NTP', value: 'NTP' },
        { text: 'SSDP', value: 'SSDP' },
        { text: 'Memcached', value: 'Memcached' },
        { text: 'TCP', value: 'TCP' },
      ],
      onFilter: (value, record) => record.protocol === value,
      render: (proto: string) => {
        const colors: Record<string, string> = {
          DNS: '#722ed1', NTP: '#fa8c16', SSDP: '#13c2c2', Memcached: '#eb2f96', TCP: '#1668dc',
        };
        return <Tag color={colors[proto] ?? 'default'}>{proto}</Tag>;
      },
    },
    {
      title: 'Violation',
      dataIndex: 'violationType',
      key: 'violationType',
      render: (v: string) => (
        <Text style={{ color: 'rgba(255,255,255,0.85)', fontSize: 13 }}>{v}</Text>
      ),
    },
    {
      title: 'Source IP',
      dataIndex: 'srcIp',
      key: 'srcIp',
      width: 140,
      render: (ip: string) => (
        <Text style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.65)' }}>{ip}</Text>
      ),
    },
    {
      title: 'Dst Port',
      dataIndex: 'dstPort',
      key: 'dstPort',
      width: 80,
      render: (p: number) => (
        <Text style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.65)' }}>{p}</Text>
      ),
    },
    {
      title: 'Count',
      dataIndex: 'count',
      key: 'count',
      width: 100,
      sorter: (a, b) => a.count - b.count,
      defaultSortOrder: 'descend',
      render: (c: number) => (
        <Text style={{ fontFamily: 'monospace', color: '#f5222d' }}>{c.toLocaleString()}</Text>
      ),
    },
    {
      title: 'Action',
      dataIndex: 'action',
      key: 'action',
      width: 100,
      render: (a: string) => (
        <Tag color={a === 'DROP' ? 'red' : 'orange'}>{a}</Tag>
      ),
    },
    {
      title: 'Last Seen',
      dataIndex: 'lastSeen',
      key: 'lastSeen',
      width: 90,
      render: (t: string) => (
        <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>{t}</Text>
      ),
    },
  ];

  // --------------- Render ---------------

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <ApiOutlined style={{ fontSize: 18, color: '#1668dc' }} />
        <Text strong style={{ fontSize: 16, color: 'rgba(255,255,255,0.85)' }}>
          Protocol Validation
        </Text>
      </div>

      {/* Stats */}
      <Row gutter={[12, 12]}>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="Protocol Violations"
              value={stats?.protoViolationDropped ?? 0}
              prefix={<StopOutlined />}
              valueStyle={{ color: '#f5222d', fontFamily: 'monospace' }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="DNS Validated"
              value={stats?.dnsQueriesValidated ?? 0}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a', fontFamily: 'monospace' }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="DNS Blocked"
              value={stats?.dnsQueriesBlocked ?? 0}
              prefix={<WarningOutlined />}
              valueStyle={{ color: '#fa8c16', fontFamily: 'monospace' }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="TCP State Violations"
              value={stats?.tcpStateViolations ?? 0}
              prefix={<SafetyOutlined />}
              valueStyle={{ color: '#722ed1', fontFamily: 'monospace' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Config + Chart */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={8}>
          <Card title="Validation Config" size="small">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* DNS Mode */}
              <div>
                <Text style={{ color: 'rgba(255,255,255,0.65)', display: 'block', marginBottom: 6 }}>
                  DNS Validation Mode
                </Text>
                <Select
                  value={dnsMode}
                  onChange={setDnsMode}
                  style={{ width: '100%' }}
                  options={[
                    { value: 0, label: 'Off' },
                    { value: 1, label: 'Basic (block amplification responses)' },
                    { value: 2, label: 'Strict (validate qdcount, opcode, size)' },
                  ]}
                />
              </div>

              <Divider style={{ margin: '4px 0' }} />

              {/* TCP State */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <Text style={{ color: 'rgba(255,255,255,0.85)' }}>TCP State Machine</Text>
                  <br />
                  <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>
                    Validate SYN/ACK/RST transitions with conntrack
                  </Text>
                </div>
                <Switch checked={tcpStateCheck} onChange={setTcpStateCheck} />
              </div>

              <Divider style={{ margin: '4px 0' }} />

              {/* NTP Monlist */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <Text style={{ color: 'rgba(255,255,255,0.85)' }}>NTP Monlist Block</Text>
                  <br />
                  <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>
                    Block mode 7 monlist amplification
                  </Text>
                </div>
                <Switch checked={ntpMonlistBlock} onChange={setNtpMonlistBlock} />
              </div>

              <Divider style={{ margin: '4px 0' }} />

              {/* SSDP */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <Text style={{ color: 'rgba(255,255,255,0.85)' }}>SSDP Reflection Block</Text>
                  <br />
                  <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>
                    Block M-SEARCH / NOTIFY responses
                  </Text>
                </div>
                <Switch checked={ssdpBlock} onChange={setSsdpBlock} />
              </div>

              <Divider style={{ margin: '4px 0' }} />

              {/* Memcached */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <Text style={{ color: 'rgba(255,255,255,0.85)' }}>Memcached UDP Block</Text>
                  <br />
                  <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>
                    Block all UDP port 11211 traffic
                  </Text>
                </div>
                <Switch checked={memcachedBlock} onChange={setMemcachedBlock} />
              </div>
            </div>

            <Divider />

            {/* Status Summary */}
            <Space direction="vertical" style={{ width: '100%' }} size={4}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <Text style={{ color: 'rgba(255,255,255,0.45)' }}>Active Validators</Text>
                <Badge
                  count={[dnsMode > 0, tcpStateCheck, ntpMonlistBlock, ssdpBlock, memcachedBlock].filter(Boolean).length}
                  style={{ backgroundColor: '#1668dc' }}
                  overflowCount={10}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <Text style={{ color: 'rgba(255,255,255,0.45)' }}>NTP Monlist Blocked</Text>
                <Text style={{ fontFamily: 'monospace', color: '#fa8c16' }}>
                  {(stats?.ntpMonlistBlocked ?? 0).toLocaleString()}
                </Text>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <Text style={{ color: 'rgba(255,255,255,0.45)' }}>Port Scans Detected</Text>
                <Text style={{ fontFamily: 'monospace', color: '#f5222d' }}>
                  {(stats?.portScanDetected ?? 0).toLocaleString()}
                </Text>
              </div>
            </Space>
          </Card>
        </Col>

        <Col xs={24} lg={16}>
          <Card title="Protocol Violation Drops (30s)" size="small">
            <ReactECharts option={chartOption} style={{ height: 320 }} notMerge />
          </Card>
        </Col>
      </Row>

      {/* Violations Table */}
      <Card title="Recent Protocol Violations" size="small">
        <Table
          columns={columns}
          dataSource={violations}
          rowKey="key"
          size="small"
          pagination={{ pageSize: 10, size: 'small' }}
        />
      </Card>
    </div>
  );
};

export default ProtoValidation;
