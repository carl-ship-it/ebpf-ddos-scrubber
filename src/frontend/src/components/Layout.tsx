import React from 'react';
import { Layout as AntLayout, Menu, Badge, Typography, Switch, Space } from 'antd';
import {
  DashboardOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
  UnorderedListOutlined,
  SettingOutlined,
  ApiOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation, Outlet } from 'react-router-dom';
import { useStore } from '../store';

const { Sider, Header, Content } = AntLayout;
const { Text } = Typography;

const menuItems = [
  { key: '/', icon: <DashboardOutlined />, label: 'Dashboard' },
  { key: '/acl', icon: <SafetyCertificateOutlined />, label: 'ACL' },
  { key: '/rate-limit', icon: <ThunderboltOutlined />, label: 'Rate Limit' },
  { key: '/events', icon: <UnorderedListOutlined />, label: 'Events' },
  { key: '/signatures', icon: <ApiOutlined />, label: 'Signatures' },
  { key: '/settings', icon: <SettingOutlined />, label: 'Settings' },
];

const AppLayout: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const collapsed = useStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useStore((s) => s.toggleSidebar);
  const connected = useStore((s) => s.connected);
  const status = useStore((s) => s.status);

  return (
    <AntLayout style={{ minHeight: '100vh' }}>
      <Sider
        collapsible
        collapsed={collapsed}
        onCollapse={toggleSidebar}
        width={220}
        style={{ borderRight: '1px solid #303030' }}
      >
        <div
          style={{
            height: 64,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderBottom: '1px solid #303030',
          }}
        >
          <Text
            strong
            style={{
              color: '#1668dc',
              fontSize: collapsed ? 16 : 18,
              letterSpacing: 1,
            }}
          >
            {collapsed ? 'DS' : 'DDoS Scrubber'}
          </Text>
        </div>

        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
          style={{ borderRight: 0 }}
        />
      </Sider>

      <AntLayout>
        <Header
          style={{
            padding: '0 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderBottom: '1px solid #303030',
            background: '#1a1a2e',
          }}
        >
          <Space>
            <Badge
              status={connected ? 'success' : 'error'}
              text={
                <Text style={{ color: 'rgba(255,255,255,0.65)' }}>
                  {connected ? 'Connected' : 'Disconnected'}
                </Text>
              }
            />
            {status && (
              <Text style={{ color: 'rgba(255,255,255,0.45)', marginLeft: 16 }}>
                {status.interfaceName} | {status.xdpMode} | v{status.version}
              </Text>
            )}
          </Space>

          <Space>
            <Text style={{ color: 'rgba(255,255,255,0.65)' }}>Scrubber</Text>
            <Switch
              checked={status?.enabled ?? false}
              checkedChildren="ON"
              unCheckedChildren="OFF"
            />
          </Space>
        </Header>

        <Content style={{ padding: 24, overflow: 'auto' }}>
          <Outlet />
        </Content>
      </AntLayout>
    </AntLayout>
  );
};

export default AppLayout;
