# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_5_0_36
  module Models
    #
    # Describes a backup policy for configuring periodic backup.
    #
    class BackupPolicyDescription

      include MsRestAzure

      # @return [String] The unique name identifying this backup policy.
      attr_accessor :name

      # @return [Boolean] Specifies whether to trigger restore automatically
      # using the latest available backup in case the partition experiences a
      # data loss event.
      attr_accessor :auto_restore_on_data_loss

      # @return [Integer] Defines the maximum number of incremental backups to
      # be taken between two full backups. This is just the upper limit. A full
      # backup may be taken before specified number of incremental backups are
      # completed in one of the following conditions
      # - The replica has never taken a full backup since it has become
      # primary,
      # - Some of the log records since the last backup has been truncated, or
      # - Replica passed the MaxAccumulatedBackupLogSizeInMB limit.
      attr_accessor :max_incremental_backups

      # @return [BackupScheduleDescription] Describes the backup schedule
      # parameters.
      attr_accessor :schedule

      # @return [BackupStorageDescription] Describes the details of backup
      # storage where to store the periodic backups.
      attr_accessor :storage

      # @return [RetentionPolicyDescription] Describes the policy to retain
      # backups in storage.
      attr_accessor :retention_policy


      #
      # Mapper for BackupPolicyDescription class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'BackupPolicyDescription',
          type: {
            name: 'Composite',
            class_name: 'BackupPolicyDescription',
            model_properties: {
              name: {
                client_side_validation: true,
                required: true,
                serialized_name: 'Name',
                type: {
                  name: 'String'
                }
              },
              auto_restore_on_data_loss: {
                client_side_validation: true,
                required: true,
                serialized_name: 'AutoRestoreOnDataLoss',
                type: {
                  name: 'Boolean'
                }
              },
              max_incremental_backups: {
                client_side_validation: true,
                required: true,
                serialized_name: 'MaxIncrementalBackups',
                constraints: {
                  InclusiveMaximum: 255,
                  InclusiveMinimum: 0
                },
                type: {
                  name: 'Number'
                }
              },
              schedule: {
                client_side_validation: true,
                required: true,
                serialized_name: 'Schedule',
                type: {
                  name: 'Composite',
                  polymorphic_discriminator: 'ScheduleKind',
                  uber_parent: 'BackupScheduleDescription',
                  class_name: 'BackupScheduleDescription'
                }
              },
              storage: {
                client_side_validation: true,
                required: true,
                serialized_name: 'Storage',
                type: {
                  name: 'Composite',
                  polymorphic_discriminator: 'StorageKind',
                  uber_parent: 'BackupStorageDescription',
                  class_name: 'BackupStorageDescription'
                }
              },
              retention_policy: {
                client_side_validation: true,
                required: false,
                serialized_name: 'RetentionPolicy',
                type: {
                  name: 'Composite',
                  polymorphic_discriminator: 'RetentionPolicyType',
                  uber_parent: 'RetentionPolicyDescription',
                  class_name: 'RetentionPolicyDescription'
                }
              }
            }
          }
        }
      end
    end
  end
end
