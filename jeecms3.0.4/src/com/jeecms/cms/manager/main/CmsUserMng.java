package com.jeecms.cms.manager.main;

import java.util.List;

import com.jeecms.cms.entity.main.CmsSite;
import com.jeecms.cms.entity.main.CmsUser;
import com.jeecms.cms.entity.main.CmsUserExt;
import com.jeecms.common.page.Pagination;

public interface CmsUserMng {
	public Pagination getPage(String username, String email, Integer siteId,
			Integer groupId, Boolean disabled, Boolean admin, Integer rank,
			int pageNo, int pageSize);

	public List<CmsUser> getAdminList(Integer siteId, Boolean allChannel,
			Boolean disabled, Integer rank);

	public CmsUser findById(Integer id);

	public CmsUser findByUsername(String username);

	public CmsUser registerMember(String username, String email,
			String password, String ip, Integer groupId, CmsUserExt userExt);

	public void updateLoginInfo(Integer userId, String ip);

	public void updateUploadSize(Integer userId, Integer size);

	public void updatePwdEmail(Integer id, String password, String email);

	public boolean isPasswordValid(Integer id, String password);

	public CmsUser saveAdmin(String username, String email, String password,
			String ip, boolean viewOnly, boolean selfAdmin, int rank,
			Integer groupId, Integer[] roleIds, Integer[] channelIds,
			Integer[] siteIds, Byte[] steps, Boolean[] allChannels,
			CmsUserExt userExt);

	public CmsUser updateAdmin(CmsUser bean, CmsUserExt ext, String password,
			Integer groupId, Integer[] roleIds, Integer[] channelIds,
			Integer[] siteIds, Byte[] steps, Boolean[] allChannels);

	public CmsUser updateMember(Integer id, String email, String password,
			Boolean isDisabled, CmsUserExt ext, Integer groupId);

	public void addSiteToUser(CmsUser user, CmsSite site, Byte checkStep);

	public CmsUser deleteById(Integer id);

	public CmsUser[] deleteByIds(Integer[] ids);

	public boolean usernameNotExist(String username);

	public boolean emailNotExist(String email);
}