import React, { useEffect, useState } from 'react';
import {
  Card,
  Descriptions,
  Switch,
  Button,
  Popconfirm,
  message,
  Row,
  Col,
  Statistic,
  Tag,
} from 'antd';
import {
  PoweroffOutlined,
  ClearOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import * as api from '../api/client';
import { useStore } from '../store';
import { formatUptime } from '../utils';
import type { ConntrackInfo } from '../types';

const SettingsPage: React.FC = () => {
  const status = useStore((s) => s.status);
  const setStatus = useStore((s) => s.setStatus);
  const [conntrack, setConntrack] = useState<ConntrackInfo | null>(null);

  useEffect(() => {
    api.getConntrackInfo().then(setConntrack).catch(() => {});
  }, []);

  const toggleEnabled = async (checked: boolean) => {
    try {
      await api.setEnabled(checked);
      if (status) {
        setStatus({ ...status, enabled: checked });
      }
      message.success(checked ? 'Scrubber enabled' : 'Scrubber disabled');
    } catch (err) {
      message.error(`Failed: ${err}`);
    }
  };

  const handleFlushConntrack = async () => {
    try {
      const result = await api.flushConntrack();
      message.success(`Flushed ${result.entriesRemoved} conntrack entries`);
      api.getConntrackInfo().then(setConntrack).catch(() => {});
    } catch (err) {
      message.error(`Failed: ${err}`);
    }
  };

  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={12}>
        <Card title="System Status">
          <Descriptions column={1} size="small">
            <Descriptions.Item label="Scrubber">
              <Switch
                checked={status?.enabled ?? false}
                onChange={toggleEnabled}
                checkedChildren="Enabled"
                unCheckedChildren="Disabled"
              />
            </Descriptions.Item>
            <Descriptions.Item label="Interface">
              <Tag>{status?.interfaceName ?? '--'}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="XDP Mode">
              <Tag color="blue">{status?.xdpMode ?? '--'}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Version">
              {status?.version ?? '--'}
            </Descriptions.Item>
            <Descriptions.Item label="Uptime">
              {status ? formatUptime(status.uptimeSeconds) : '--'}
            </Descriptions.Item>
            <Descriptions.Item label="Program ID">
              {status?.programId ?? '--'}
            </Descriptions.Item>
          </Descriptions>
        </Card>
      </Col>

      <Col xs={24} lg={12}>
        <Card title="Connection Tracking">
          <Row gutter={16} style={{ marginBottom: 16 }}>
            <Col span={12}>
              <Statistic
                title="Active Connections"
                value={conntrack?.activeConnections ?? 0}
              />
            </Col>
            <Col span={12}>
              <Statistic
                title="Status"
                value={conntrack?.enabled ? 'Enabled' : 'Disabled'}
                valueStyle={{
                  color: conntrack?.enabled ? '#52c41a' : '#f5222d',
                }}
              />
            </Col>
          </Row>

          <Popconfirm
            title="Flush all conntrack entries?"
            description="This will remove all tracked connections. Existing connections may be briefly disrupted."
            onConfirm={handleFlushConntrack}
          >
            <Button icon={<ClearOutlined />} danger>
              Flush Conntrack
            </Button>
          </Popconfirm>
        </Card>
      </Col>
    </Row>
  );
};

export default SettingsPage;
