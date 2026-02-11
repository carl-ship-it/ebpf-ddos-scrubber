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
  InputNumber,
  Select,
  Switch,
  Checkbox,
  Space,
  Descriptions,
  Divider,
  Typography,
  message,
  Popconfirm,
} from 'antd';
import {
  PlusOutlined,
  DeleteOutlined,
  ClusterOutlined,
  LinkOutlined,
  DisconnectOutlined,
  SaveOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';
import { formatUptime } from '../utils';

const { Text } = Typography;

// --------------- Types ---------------

interface BGPConfig {
  enabled: boolean;
  routerIp: string;
  localAs: number;
  peerAs: number;
  community: string;
  autoTriggerCritical: boolean;
}

interface RTBHEntry {
  key: string;
  prefix: string;
  reason: string;
  createdAt: string;
}

interface FlowspecRule {
  key: string;
  srcPrefix: string;
  dstPrefix: string;
  protocol: string;
  srcPort: string;
  dstPort: string;
  action: string;
  createdAt: string;
}

// --------------- Mock data ---------------

const initialConfig: BGPConfig = {
  enabled: true,
  routerIp: '10.0.0.1',
  localAs: 65001,
  peerAs: 65000,
  community: '65000:666',
  autoTriggerCritical: true,
};

const initialRTBH: RTBHEntry[] = [
  {
    key: 'rtbh-1',
    prefix: '198.51.100.0/24',
    reason: 'Volumetric UDP flood source',
    createdAt: dayjs().subtract(45, 'minute').format('YYYY-MM-DD HH:mm:ss'),
  },
  {
    key: 'rtbh-2',
    prefix: '203.0.113.128/25',
    reason: 'SYN flood from botnet C2 range',
    createdAt: dayjs().subtract(2, 'hour').format('YYYY-MM-DD HH:mm:ss'),
  },
  {
    key: 'rtbh-3',
    prefix: '192.0.2.64/26',
    reason: 'DNS amplification reflectors',
    createdAt: dayjs().subtract(4, 'hour').format('YYYY-MM-DD HH:mm:ss'),
  },
];

const initialFlowspec: FlowspecRule[] = [
  {
    key: 'fs-1',
    srcPrefix: '0.0.0.0/0',
    dstPrefix: '10.1.0.0/16',
    protocol: 'UDP',
    srcPort: '*',
    dstPort: '53',
    action: 'rate-limit 1000',
    createdAt: dayjs().subtract(30, 'minute').format('YYYY-MM-DD HH:mm:ss'),
  },
  {
    key: 'fs-2',
    srcPrefix: '198.51.100.0/24',
    dstPrefix: '10.1.0.0/16',
    protocol: 'TCP',
    srcPort: '*',
    dstPort: '80,443',
    action: 'discard',
    createdAt: dayjs().subtract(1, 'hour').format('YYYY-MM-DD HH:mm:ss'),
  },
  {
    key: 'fs-3',
    srcPrefix: '0.0.0.0/0',
    dstPrefix: '10.1.0.0/16',
    protocol: 'UDP',
    srcPort: '123',
    dstPort: '*',
    action: 'rate-limit 500',
    createdAt: dayjs().subtract(2, 'hour').format('YYYY-MM-DD HH:mm:ss'),
  },
];

// --------------- Component ---------------

const BGP: React.FC = () => {
  const [config, setConfig] = useState<BGPConfig>(initialConfig);
  const [configForm] = Form.useForm<BGPConfig>();
  const [rtbhEntries, setRtbhEntries] = useState<RTBHEntry[]>(initialRTBH);
  const [flowspecRules, setFlowspecRules] = useState<FlowspecRule[]>(initialFlowspec);
  const [blackholeModalOpen, setBlackholeModalOpen] = useState(false);
  const [flowspecModalOpen, setFlowspecModalOpen] = useState(false);
  const [blackholeForm] = Form.useForm();
  const [flowspecForm] = Form.useForm();

  // Mock session state
  const sessionConnected = config.enabled;
  const sessionUptime = 14523; // ~4 hours

  // --------------- Handlers ---------------

  const handleSaveConfig = async () => {
    try {
      const values = await configForm.validateFields();
      setConfig(values);
      message.success('BGP configuration saved');
    } catch {
      // validation error
    }
  };

  const handleResetConfig = () => {
    configForm.setFieldsValue(config);
  };

  const handleWithdrawRTBH = (key: string) => {
    setRtbhEntries((prev) => prev.filter((e) => e.key !== key));
    message.success('RTBH blackhole withdrawn');
  };

  const handleAddBlackhole = async () => {
    try {
      const values = await blackholeForm.validateFields();
      const entry: RTBHEntry = {
        key: `rtbh-${Date.now()}`,
        prefix: values.prefix,
        reason: values.reason || 'Manually announced',
        createdAt: dayjs().format('YYYY-MM-DD HH:mm:ss'),
      };
      setRtbhEntries((prev) => [...prev, entry]);
      setBlackholeModalOpen(false);
      blackholeForm.resetFields();
      message.success(`RTBH announced for ${values.prefix}`);
    } catch {
      // validation error
    }
  };

  const handleRemoveFlowspec = (key: string) => {
    setFlowspecRules((prev) => prev.filter((r) => r.key !== key));
    message.success('Flowspec rule removed');
  };

  const handleAddFlowspec = async () => {
    try {
      const values = await flowspecForm.validateFields();
      const rule: FlowspecRule = {
        key: `fs-${Date.now()}`,
        srcPrefix: values.srcPrefix || '0.0.0.0/0',
        dstPrefix: values.dstPrefix || '0.0.0.0/0',
        protocol: values.protocol,
        srcPort: values.srcPort || '*',
        dstPort: values.dstPort || '*',
        action: values.action,
        createdAt: dayjs().format('YYYY-MM-DD HH:mm:ss'),
      };
      setFlowspecRules((prev) => [...prev, rule]);
      setFlowspecModalOpen(false);
      flowspecForm.resetFields();
      message.success('Flowspec rule added');
    } catch {
      // validation error
    }
  };

  // --------------- RTBH table columns ---------------

  const rtbhColumns: ColumnsType<RTBHEntry> = [
    {
      title: 'Prefix',
      dataIndex: 'prefix',
      key: 'prefix',
      render: (p: string) => (
        <Text style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.85)' }}>{p}</Text>
      ),
    },
    {
      title: 'Reason',
      dataIndex: 'reason',
      key: 'reason',
      render: (r: string) => <Text style={{ color: 'rgba(255,255,255,0.65)' }}>{r}</Text>,
    },
    {
      title: 'Created At',
      dataIndex: 'createdAt',
      key: 'createdAt',
      width: 170,
      render: (t: string) => (
        <Text style={{ color: 'rgba(255,255,255,0.45)', fontFamily: 'monospace', fontSize: 12 }}>{t}</Text>
      ),
    },
    {
      title: 'Action',
      key: 'action',
      width: 120,
      render: (_: unknown, record: RTBHEntry) => (
        <Popconfirm
          title={`Withdraw blackhole for ${record.prefix}?`}
          onConfirm={() => handleWithdrawRTBH(record.key)}
        >
          <Button size="small" danger icon={<DeleteOutlined />}>
            Withdraw
          </Button>
        </Popconfirm>
      ),
    },
  ];

  // --------------- Flowspec table columns ---------------

  const flowspecColumns: ColumnsType<FlowspecRule> = [
    {
      title: 'Src Prefix',
      dataIndex: 'srcPrefix',
      key: 'srcPrefix',
      render: (p: string) => (
        <Text style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>{p}</Text>
      ),
    },
    {
      title: 'Dst Prefix',
      dataIndex: 'dstPrefix',
      key: 'dstPrefix',
      render: (p: string) => (
        <Text style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.85)', fontSize: 12 }}>{p}</Text>
      ),
    },
    {
      title: 'Protocol',
      dataIndex: 'protocol',
      key: 'protocol',
      width: 90,
      render: (p: string) => {
        const colors: Record<string, string> = { TCP: 'blue', UDP: 'orange', ICMP: 'green' };
        return <Tag color={colors[p] ?? 'default'}>{p}</Tag>;
      },
    },
    {
      title: 'Src Port',
      dataIndex: 'srcPort',
      key: 'srcPort',
      width: 80,
      render: (p: string) => (
        <Text style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.65)', fontSize: 12 }}>{p}</Text>
      ),
    },
    {
      title: 'Dst Port',
      dataIndex: 'dstPort',
      key: 'dstPort',
      width: 80,
      render: (p: string) => (
        <Text style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.65)', fontSize: 12 }}>{p}</Text>
      ),
    },
    {
      title: 'Action',
      dataIndex: 'action',
      key: 'action',
      width: 140,
      render: (a: string) => {
        const color = a === 'discard' ? 'red' : 'orange';
        return <Tag color={color}>{a}</Tag>;
      },
    },
    {
      title: 'Created At',
      dataIndex: 'createdAt',
      key: 'createdAt',
      width: 170,
      render: (t: string) => (
        <Text style={{ color: 'rgba(255,255,255,0.45)', fontFamily: 'monospace', fontSize: 12 }}>{t}</Text>
      ),
    },
    {
      title: '',
      key: 'actions',
      width: 80,
      render: (_: unknown, record: FlowspecRule) => (
        <Popconfirm
          title="Remove this Flowspec rule?"
          onConfirm={() => handleRemoveFlowspec(record.key)}
        >
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  // --------------- Render ---------------

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <ClusterOutlined style={{ fontSize: 18, color: '#1668dc' }} />
        <Text strong style={{ fontSize: 16, color: 'rgba(255,255,255,0.85)' }}>
          BGP Flowspec &amp; RTBH
        </Text>
      </div>

      {/* Row 1: Session Status + Configuration */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={8}>
          <Card
            title="BGP Session Status"
            size="small"
            style={{ height: '100%' }}
            extra={
              sessionConnected ? (
                <Badge status="success" text={<Text style={{ color: '#52c41a' }}>Connected</Text>} />
              ) : (
                <Badge status="error" text={<Text style={{ color: '#f5222d' }}>Disconnected</Text>} />
              )
            }
          >
            <Descriptions column={1} size="small" style={{ marginTop: 8 }}>
              <Descriptions.Item label="Router IP">
                <Text style={{ fontFamily: 'monospace' }}>{config.routerIp}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Local AS">
                <Text style={{ fontFamily: 'monospace' }}>{config.localAs}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Peer AS">
                <Text style={{ fontFamily: 'monospace' }}>{config.peerAs}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Session State">
                {sessionConnected ? (
                  <Tag color="green" icon={<LinkOutlined />}>Established</Tag>
                ) : (
                  <Tag color="red" icon={<DisconnectOutlined />}>Idle</Tag>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="Uptime">
                <Text style={{ fontFamily: 'monospace' }}>
                  {sessionConnected ? formatUptime(sessionUptime) : '--'}
                </Text>
              </Descriptions.Item>
              <Descriptions.Item label="Community">
                <Tag>{config.community}</Tag>
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>

        <Col xs={24} lg={16}>
          <Card title="BGP Configuration" size="small">
            <Form
              form={configForm}
              layout="vertical"
              initialValues={config}
            >
              <Row gutter={16}>
                <Col span={24}>
                  <Form.Item name="enabled" valuePropName="checked" label="BGP Integration">
                    <Switch checkedChildren="Enabled" unCheckedChildren="Disabled" />
                  </Form.Item>
                </Col>
              </Row>

              <Divider orientation="left" plain style={{ margin: '8px 0 16px' }}>
                Peering
              </Divider>

              <Row gutter={16}>
                <Col xs={24} md={8}>
                  <Form.Item
                    name="routerIp"
                    label="Router IP"
                    rules={[{ required: true, message: 'Required' }]}
                  >
                    <Input placeholder="10.0.0.1" style={{ fontFamily: 'monospace' }} />
                  </Form.Item>
                </Col>
                <Col xs={24} md={8}>
                  <Form.Item
                    name="localAs"
                    label="Local AS"
                    rules={[{ required: true, message: 'Required' }]}
                  >
                    <InputNumber min={1} max={4294967295} style={{ width: '100%', fontFamily: 'monospace' }} />
                  </Form.Item>
                </Col>
                <Col xs={24} md={8}>
                  <Form.Item
                    name="peerAs"
                    label="Peer AS"
                    rules={[{ required: true, message: 'Required' }]}
                  >
                    <InputNumber min={1} max={4294967295} style={{ width: '100%', fontFamily: 'monospace' }} />
                  </Form.Item>
                </Col>
              </Row>

              <Row gutter={16}>
                <Col xs={24} md={12}>
                  <Form.Item
                    name="community"
                    label="Blackhole Community"
                    tooltip="BGP community string used for RTBH announcements"
                    rules={[{ required: true, message: 'Required' }]}
                  >
                    <Input placeholder="65000:666" style={{ fontFamily: 'monospace' }} />
                  </Form.Item>
                </Col>
                <Col xs={24} md={12}>
                  <Form.Item
                    name="autoTriggerCritical"
                    valuePropName="checked"
                    label=" "
                    style={{ marginTop: 4 }}
                  >
                    <Checkbox>Auto-trigger BGP at CRITICAL escalation level</Checkbox>
                  </Form.Item>
                </Col>
              </Row>

              <Form.Item style={{ marginBottom: 0 }}>
                <Space>
                  <Button type="primary" icon={<SaveOutlined />} onClick={handleSaveConfig}>
                    Save
                  </Button>
                  <Button icon={<ReloadOutlined />} onClick={handleResetConfig}>
                    Reset
                  </Button>
                </Space>
              </Form.Item>
            </Form>
          </Card>
        </Col>
      </Row>

      {/* Active RTBH Blackholes */}
      <Card
        title="Active RTBH Blackholes"
        size="small"
        extra={
          <Button
            type="primary"
            icon={<PlusOutlined />}
            size="small"
            onClick={() => setBlackholeModalOpen(true)}
          >
            Announce Blackhole
          </Button>
        }
      >
        <Table
          columns={rtbhColumns}
          dataSource={rtbhEntries}
          rowKey="key"
          size="small"
          pagination={false}
        />
      </Card>

      {/* Active Flowspec Rules */}
      <Card
        title="Active Flowspec Rules"
        size="small"
        extra={
          <Button
            type="primary"
            icon={<PlusOutlined />}
            size="small"
            onClick={() => setFlowspecModalOpen(true)}
          >
            Add Rule
          </Button>
        }
      >
        <Table
          columns={flowspecColumns}
          dataSource={flowspecRules}
          rowKey="key"
          size="small"
          pagination={false}
        />
      </Card>

      {/* Announce Blackhole Modal */}
      <Modal
        title="Announce RTBH Blackhole"
        open={blackholeModalOpen}
        onOk={handleAddBlackhole}
        onCancel={() => setBlackholeModalOpen(false)}
        okText="Announce"
        width={460}
      >
        <Form form={blackholeForm} layout="vertical">
          <Form.Item
            name="prefix"
            label="Prefix (CIDR)"
            rules={[
              { required: true, message: 'Please enter a prefix' },
              {
                pattern: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/,
                message: 'Enter a valid CIDR (e.g. 192.0.2.0/24)',
              },
            ]}
          >
            <Input placeholder="192.0.2.0/24" style={{ fontFamily: 'monospace' }} />
          </Form.Item>
          <Form.Item name="reason" label="Reason (optional)">
            <Input placeholder="e.g. Volumetric attack source" />
          </Form.Item>
        </Form>
      </Modal>

      {/* Add Flowspec Rule Modal */}
      <Modal
        title="Add Flowspec Rule"
        open={flowspecModalOpen}
        onOk={handleAddFlowspec}
        onCancel={() => setFlowspecModalOpen(false)}
        okText="Add Rule"
        width={560}
      >
        <Form form={flowspecForm} layout="vertical">
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="srcPrefix" label="Source Prefix">
                <Input placeholder="0.0.0.0/0" style={{ fontFamily: 'monospace' }} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="dstPrefix" label="Destination Prefix">
                <Input placeholder="10.1.0.0/16" style={{ fontFamily: 'monospace' }} />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={8}>
              <Form.Item
                name="protocol"
                label="Protocol"
                rules={[{ required: true, message: 'Required' }]}
              >
                <Select
                  options={[
                    { label: 'TCP', value: 'TCP' },
                    { label: 'UDP', value: 'UDP' },
                    { label: 'ICMP', value: 'ICMP' },
                    { label: 'Any', value: 'Any' },
                  ]}
                />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="srcPort" label="Source Port">
                <Input placeholder="*" style={{ fontFamily: 'monospace' }} />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="dstPort" label="Destination Port">
                <Input placeholder="53" style={{ fontFamily: 'monospace' }} />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item
            name="action"
            label="Action"
            rules={[{ required: true, message: 'Required' }]}
          >
            <Select
              options={[
                { label: 'Discard', value: 'discard' },
                { label: 'Rate-limit 500 pps', value: 'rate-limit 500' },
                { label: 'Rate-limit 1000 pps', value: 'rate-limit 1000' },
                { label: 'Rate-limit 5000 pps', value: 'rate-limit 5000' },
                { label: 'Redirect to scrubber', value: 'redirect' },
              ]}
            />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default BGP;
